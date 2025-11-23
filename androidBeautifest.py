#!/usr/bin/env python3
"""
Analyzes APKs looking for potentially exploitable Android components
based on the AndroidManifest.xml using a static analysis engine.

Usage:
  python androidBeautifest.py target.apk
"""

import os
import sys
import argparse
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

from colorama import Fore, Style, init

# engine (androguard)
import logging
from androguard.misc import AnalyzeAPK

# logs off
logging.getLogger("androguard").setLevel(logging.ERROR)
logging.getLogger("androguard.core").setLevel(logging.ERROR)
logging.getLogger("androguard.axml").setLevel(logging.ERROR)

# logs off
try:
    from loguru import logger as loguru_logger
    loguru_logger.remove()
except Exception:
    pass

# init colors
init(autoreset=True)


class AndroidBeautifest:
    def __init__(self, apk_path: str) -> None:
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path).replace(".apk", "")
        self.ns = "{http://schemas.android.com/apk/res/android}"  # android namespace
        self.report_content: List[str] = []

    def log(self, text: str, color: str = Fore.WHITE, save: bool = True) -> None:
        print(f"{color}{text}{Style.RESET_ALL}")
        if save:
            self.report_content.append(text)

    # ENGINE
    def parse_with_engine(self) -> None:
        # analyze APK
        sep = "=" * 80
        self.log(f"\n{sep}", Fore.WHITE)
        self.log(f"[*] Analyzing {self.apk_path} ...", Fore.WHITE)
        self.log(f"{sep}\n", Fore.WHITE)

        try:
            apk, d, dx = AnalyzeAPK(self.apk_path)
        except Exception as e:
            self.log(f"[!] Error: {e}", Fore.RED)
            sys.exit(1)

        manifest_xml = apk.get_android_manifest_xml()
        if hasattr(manifest_xml, "getroot"):
            root = manifest_xml.getroot()
        else:
            root = manifest_xml

        package_name = apk.get_package()
        version_code = apk.get_androidversion_code() or "N/A"
        version_name = apk.get_androidversion_name() or "N/A"

        self._parse_manifest_root(root, package_name, str(version_code), str(version_name))

    # HELPERS XML
    def get_attrib(self, elem: ET.Element, attr_name: str) -> Optional[str]:
        # get an attribute using the android namespace
        return elem.attrib.get(f"{self.ns}{attr_name}")

    def _find_first(self, root: ET.Element, suffix: str) -> Optional[ET.Element]:
        # find first element whose tag ends with suffix
        for el in root.iter():
            if el.tag.endswith(suffix):
                return el
        return None

    # COMMON ANALYSIS
    def _parse_manifest_root(
        self,
        root: ET.Element,
        package_name: str,
        version_code: str,
        version_name: str,
    ) -> None:
        # common analysis logic for manifest root
        sep = "=" * 80
        self.log(f"\n{sep}", Fore.WHITE)
        self.log("AndroidBeautifest - Android Manifest Analyzer", Fore.WHITE)
        self.log("https://lautarovculic.com - Lautaro Villarreal Culic'", Fore.WHITE)
        self.log(sep, Fore.WHITE)
        self.log("", Fore.WHITE)

        self.log(f"Target APK:   {self.apk_name}.apk", Fore.WHITE)
        self.log(f"Package Name: {package_name}", Fore.WHITE)
        self.log(f"Version Code: {version_code}", Fore.WHITE)
        self.log(f"Version Name: {version_name}", Fore.WHITE)
        self.log("-" * 80 + "\n", Fore.WHITE)

        # insecure application-level configuration
        self.analyze_insecure_configs(root)

        # package visibility (queries)
        self.analyze_queries(root)

        # exported components
        self.analyze_components(root, package_name)

    def is_generic(self, component_name: str) -> bool:
        # filter out generic components from firebase, google, etc
        generics = [
            "com.google.firebase",
            "com.google.android.gms",
            "androidx.",
            "android.support.",
            "com.facebook.",
            "com.android.vending",
            "com.google.android.play",
            "com.crashlytics.",
            "io.fabric.sdk",
            "com.android.installreferrer",
        ]
        return any(g in component_name for g in generics)

    # Application-level config
    def analyze_insecure_configs(self, root: ET.Element) -> None:
        # analyze insecure but commonly exploitable application-level configuration
        app = self._find_first(root, "application")
        if app is None:
            return

        issues: List[Dict[str, Any]] = []

        # debuggable=true
        if self.get_attrib(app, "debuggable") == "true":
            issues.append(
                {
                    "level": "CRITICAL",
                    "name": "debuggable=true",
                    "description": "Application is debuggable. This allows JDWP attachment, memory inspection, and easier runtime tampering.",
                    "hint": "Use a non-debuggable build for production (remove android:debuggable or set it to false).",
                }
            )

        # allowBackup sin backup config
        if self.get_attrib(app, "allowBackup") == "true":
            backup_agent = self.get_attrib(app, "backupAgent")
            full_backup = self.get_attrib(app, "fullBackupContent")

            desc = "Backup is enabled. User data (databases, SharedPreferences, files) may be extracted with adb backup."
            if not backup_agent and not full_backup:
                desc += " No custom backup policy was found."
            issues.append(
                {
                    "level": "HIGH",
                    "name": "allowBackup=true",
                    "description": desc,
                    "hint": "Disable backups or explicitly define a restrictive backup policy.",
                }
            )

        # usesCleartextTraffic
        if self.get_attrib(app, "usesCleartextTraffic") == "true":
            issues.append(
                {
                    "level": "HIGH",
                    "name": "usesCleartextTraffic=true",
                    "description": "Cleartext HTTP traffic is allowed. This may be abused for network interception and tampering on untrusted networks.",
                    "hint": "Restrict cleartext traffic and enforce TLS in network security configuration.",
                }
            )

        # testOnly
        if self.get_attrib(app, "testOnly") == "true":
            issues.append(
                {
                    "level": "MEDIUM",
                    "name": "testOnly=true",
                    "description": "Application is marked as testOnly. This flag should not normally appear in production builds.",
                    "hint": "Remove android:testOnly for production builds.",
                }
            )

        # networkSecurityConfig
        nsc = self.get_attrib(app, "networkSecurityConfig")
        if nsc:
            issues.append(
                {
                    "level": "INFO",
                    "name": f"networkSecurityConfig={nsc}",
                    "description": "Custom network security configuration is in use. It may relax certificate or cleartext restrictions.",
                    "hint": "Review res/xml network security configuration manually.",
                }
            )

        if not issues:
            return

        sep = "=" * 80
        self.log("[*] Application-level configuration findings:", Fore.WHITE)
        self.log(sep, Fore.WHITE)

        for issue in issues:
            if issue["level"] == "CRITICAL":
                header_color = Fore.RED
            else:
                header_color = Fore.WHITE

            self.log(f"[{issue['level']}] {issue['name']}", header_color)
            self.log(f"    Description: {issue['description']}", Fore.WHITE)
            self.log(f"    Hint: {issue['hint']}", Fore.WHITE)
            self.log("", Fore.WHITE)

        self.log(sep + "\n", Fore.WHITE)

    # queries/package visibility
    def analyze_queries(self, root: ET.Element) -> None:
        # analyze <queries> for package visibility
        queries = self._find_first(root, "queries")
        if queries is None:
            return

        found_queries = []

        for child in queries:
            if child.tag.endswith("package"):
                p_name = self.get_attrib(child, "name")
                if p_name:
                    found_queries.append(("package", p_name))
            elif child.tag.endswith("intent"):
                actions = []
                for action in child:
                    if action.tag.endswith("action"):
                        act_name = self.get_attrib(action, "name")
                        if act_name:
                            actions.append(act_name)
                if actions:
                    found_queries.append(("intent", ", ".join(actions)))

        if found_queries:
            self.log("[*] Package visibility (queries):", Fore.WHITE)
            self.log("    The app can query:", Fore.WHITE)
            for q_type, q_value in found_queries:
                prefix = "    - PACKAGE:" if q_type == "package" else "    - INTENT:"
                self.log(f"{prefix} {q_value}", Fore.WHITE)
            self.log("", Fore.WHITE)

    # Components
    def analyze_components(self, root: ET.Element, package_name: str) -> None:
        # analyze components looking for exported entry points
        component_types = ["activity", "activity-alias", "service", "receiver", "provider"]

        all_components: List[Dict[str, Any]] = []
        unprotected_exported_count = 0

        application = self._find_first(root, "application")
        if application is None:
            return

        for elem in application:
            c_type = None
            for ct in component_types:
                if elem.tag.endswith(ct):
                    c_type = ct
                    break
            if not c_type:
                continue

            name = self.get_attrib(elem, "name")
            if not name:
                continue

            # normalize component name
            if name.startswith("."):
                full_name = package_name + name
            elif "." not in name:
                full_name = package_name + "." + name
            else:
                full_name = name

            if self.is_generic(full_name):
                continue

            # exported
            exported_attr = self.get_attrib(elem, "exported")
            has_intent_filters = any(child.tag.endswith("intent-filter") for child in elem)

            if exported_attr is None:
                is_exported = has_intent_filters
            else:
                is_exported = exported_attr == "true"

            # permissions
            permission = self.get_attrib(elem, "permission")
            read_permission = self.get_attrib(elem, "readPermission")
            write_permission = self.get_attrib(elem, "writePermission")

            has_protection = bool(permission or read_permission or write_permission)

            is_unprotected_exported = is_exported and not has_protection
            if is_unprotected_exported:
                unprotected_exported_count += 1

            intent_actions = self.get_intent_actions(elem)
            deep_links = self.extract_deep_links(elem)

            authority = self.get_attrib(elem, "authorities")
            grant_uri_permissions = self.get_attrib(elem, "grantUriPermissions")

            all_components.append(
                {
                    "type": c_type,
                    "name": full_name,
                    "exported": is_exported,
                    "unprotected_exported": is_unprotected_exported,
                    "permission": permission,
                    "read_permission": read_permission,
                    "write_permission": write_permission,
                    "authority": authority,
                    "grant_uri_permissions": grant_uri_permissions,
                    "deep_links": deep_links,
                    "intent_actions": intent_actions,
                    "has_intent_filters": has_intent_filters,
                }
            )

        all_components.sort(
            key=lambda x: (
                not x["unprotected_exported"],
                not x["exported"],
                x["type"],
            )
        )

        exported_count = sum(1 for c in all_components if c["exported"])

        sep = "=" * 80
        self.log(
            f"[*] Components analyzed ({len(all_components)} total, {exported_count} exported, {unprotected_exported_count} exported without permission):",
            Fore.WHITE,
        )
        self.log(sep + "\n", Fore.WHITE)

        for comp in all_components:
            self.display_component(comp, package_name)

    def get_intent_actions(self, elem: ET.Element) -> List[str]:
        # extract actions from intent-filters
        actions: List[str] = []
        for child in elem:
            if not child.tag.endswith("intent-filter"):
                continue
            for action in child:
                if action.tag.endswith("action"):
                    act_name = self.get_attrib(action, "name")
                    if act_name:
                        actions.append(act_name)
        return actions

    def extract_deep_links(self, elem: ET.Element) -> List[str]:
        # extract deep links and app links
        links: List[str] = []
        for intent_filter in elem:
            if not intent_filter.tag.endswith("intent-filter"):
                continue

            auto_verify = self.get_attrib(intent_filter, "autoVerify") == "true"

            schemes = set()
            hosts = set()
            ports = set()
            paths: List[str] = []
            path_prefixes: List[str] = []
            path_patterns: List[str] = []

            for data in intent_filter:
                if not data.tag.endswith("data"):
                    continue
                s = self.get_attrib(data, "scheme")
                h = self.get_attrib(data, "host")
                port = self.get_attrib(data, "port")
                p = self.get_attrib(data, "path")
                pp = self.get_attrib(data, "pathPrefix")
                ppa = self.get_attrib(data, "pathPattern")

                if s:
                    schemes.add(s)
                if h:
                    hosts.add(h)
                if port:
                    ports.add(port)
                if p:
                    paths.append(p)
                if pp:
                    path_prefixes.append(pp)
                if ppa:
                    path_patterns.append(ppa)

            for scheme in schemes:
                if hosts:
                    for host in hosts:
                        base = f"{scheme}://{host}"
                        if ports:
                            for port in ports:
                                base_with_port = f"{base}:{port}"
                                links.extend(
                                    self._build_paths(
                                        base_with_port,
                                        paths,
                                        path_prefixes,
                                        path_patterns,
                                        auto_verify,
                                    )
                                )
                        else:
                            links.extend(
                                self._build_paths(
                                    base, paths, path_prefixes, path_patterns, auto_verify
                                )
                            )
                else:
                    links.extend(
                        self._build_paths(
                            f"{scheme}://", paths, path_prefixes, path_patterns, auto_verify
                        )
                    )

        return links

    def _build_paths(
        self,
        base: str,
        paths: List[str],
        prefixes: List[str],
        patterns: List[str],
        auto_verify: bool,
    ) -> List[str]:
        # build all path combinations for deep links
        result: List[str] = []
        link_type = "APP_LINK" if auto_verify else "DEEP_LINK"

        if paths:
            for p in paths:
                result.append(f"{link_type} {base}{p}")
        elif prefixes:
            for pp in prefixes:
                result.append(f"{link_type} {base}{pp}*")
        elif patterns:
            for ppa in patterns:
                result.append(f"{link_type} {base}{ppa}")
        else:
            result.append(f"{link_type} {base}")

        return result

    def display_component(self, comp: Dict[str, Any], package_name: str) -> None:
        # display a component and its security-relevant properties
        if comp["unprotected_exported"]:
            status_color = Fore.RED
            type_name_color = Fore.WHITE
            status = "[UNPROTECTED EXPORTED COMPONENT]"
        elif comp["exported"]:
            status_color = Fore.WHITE
            type_name_color = Fore.WHITE
            status = "[EXPORTED COMPONENT]"
        else:
            status_color = Fore.BLUE
            type_name_color = Fore.BLUE
            status = "[NOT EXPORTED]"

        self.log("\n" + "-" * 80, Fore.WHITE)
        self.log(status, status_color)
        self.log(f"Type: {comp['type']}", type_name_color)
        self.log(f"Name: {comp['name']}", type_name_color)

        if comp["exported"]:
            if comp["permission"]:
                self.log(f"  Permission: {comp['permission']}", Fore.WHITE)
            if comp["read_permission"]:
                self.log(f"  Read permission: {comp['read_permission']}", Fore.WHITE)
            if comp["write_permission"]:
                self.log(f"  Write permission: {comp['write_permission']}", Fore.WHITE)

            if not comp["permission"] and not comp["read_permission"] and not comp["write_permission"]:
                self.log(
                    "  Note: exported without an explicit permission. Any installed app may be able to interact with it.",
                    Fore.RED if comp["unprotected_exported"] else Fore.WHITE,
                )

        if comp["intent_actions"]:
            self.log("  Intent actions:", Fore.WHITE)
            for action in comp["intent_actions"]:
                short_action = action.split(".")[-1] if "." in action else action
                self.log(f"    - {short_action} ({action})", Fore.WHITE)

        if comp["deep_links"]:
            self.log("  Deep links / app links:", Fore.WHITE)
            for dl in comp["deep_links"]:
                self.log(f"    - {dl}", Fore.WHITE)

        if comp["type"] == "provider" and comp["authority"]:
            self.log(f"  Authority: {comp['authority']}", Fore.WHITE)
            if comp["grant_uri_permissions"] == "true":
                self.log(
                    "  Note: grantUriPermissions=true, URIs may be shared with temporary access.",
                    Fore.WHITE,
                )

        # visual separator
        self.log("", Fore.WHITE)
        self.log("  Example attack commands:", Fore.WHITE)
        self.log("", Fore.WHITE)
        self.generate_attack_commands(comp, package_name)

    def generate_attack_commands(self, comp: Dict[str, Any], package_name: str) -> None:
        # generate adb commands that can be used to interact with the component
        c_type = comp["type"]
        c_name = comp["name"]
        cmd_color = Fore.GREEN  # green commands

        def cmd(line: str) -> None:
            self.log(f"    > {line}", cmd_color)

        if c_type in ["activity", "activity-alias"]:
            cmd(f"adb shell am start -n {package_name}/{c_name}")

            if comp["deep_links"]:
                for dl in comp["deep_links"]:
                    uri = dl.split(" ", 1)[-1] if " " in dl else dl
                    cmd(
                        f'adb shell am start -W -a android.intent.action.VIEW -d "{uri}" {package_name}'
                    )

            if comp["unprotected_exported"]:
                cmd("# With arbitrary extras:")
                cmd(
                    f'adb shell am start -n {package_name}/{c_name} --es "param" "../../../etc/passwd"'
                )
                cmd(
                    f'adb shell am start -n {package_name}/{c_name} --es "url" "javascript:alert(1)"'
                )

        elif c_type == "service":
            cmd(f"adb shell am startservice -n {package_name}/{c_name}")
            if comp["unprotected_exported"]:
                cmd("# With arbitrary extras:")
                cmd(
                    f'adb shell am startservice -n {package_name}/{c_name} --es "cmd" "id"'
                )

        elif c_type == "receiver":
            cmd(f"adb shell am broadcast -n {package_name}/{c_name}")

            if comp["intent_actions"]:
                for action in comp["intent_actions"][:2]:
                    cmd(
                        f"adb shell am broadcast -a {action} -n {package_name}/{c_name}"
                    )

            if comp["unprotected_exported"]:
                cmd("# With arbitrary extras:")
                cmd(
                    f'adb shell am broadcast -n {package_name}/{c_name} --es "data" "payload"'
                )

        elif c_type == "provider" and comp["authority"]:
            auth = comp["authority"]
            cmd("# Query:")
            cmd(f"adb shell content query --uri content://{auth}/")

            if comp["unprotected_exported"]:
                cmd("# Try simple traversal / enumeration:")
                cmd(f"adb shell content query --uri content://{auth}/../../")
                cmd("# Insert:")
                cmd(
                    f"adb shell content insert --uri content://{auth}/ --bind column:s:value"
                )
                cmd("# Update:")
                cmd(
                    f"adb shell content update --uri content://{auth}/ --bind column:s:newvalue"
                )
                cmd("# Delete:")
                cmd(f"adb shell content delete --uri content://{auth}/")
                cmd("# Simple SQL injection probe:")
                cmd(
                    f'adb shell content query --uri "content://{auth}/\' OR \'1\'=\'1\""'
                )

    def save_report(self) -> None:
        # persist the report to a .txt file
        filename = f"report_{self.apk_name}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(self.report_content))
        print(f"\n{Fore.WHITE}[*] Report saved to: {filename}{Style.RESET_ALL}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Android Manifest Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python androidBeautifest.py target.apk
        """,
    )
    parser.add_argument("apk", help="Path to the .apk file")
    args = parser.parse_args()

    if not os.path.isfile(args.apk):
        print(f"{Fore.RED}[!] File does not exist: {args.apk}{Style.RESET_ALL}")
        return

    tool = AndroidBeautifest(args.apk)
    tool.parse_with_engine()
    tool.save_report()


if __name__ == "__main__":
    main()
