import os
import tempfile
import logging

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uvicorn

from androguard.misc import AnalyzeAPK

# logs off
logging.getLogger("androguard").setLevel(logging.ERROR)
logging.getLogger("androguard.core").setLevel(logging.ERROR)
logging.getLogger("androguard.axml").setLevel(logging.ERROR)

try:
    from loguru import logger as loguru_logger
    loguru_logger.remove()
except Exception:
    pass

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# XML helpers
def _get_attr(elem, name, default=None):
    for k, v in elem.attrib.items():
        if k == name or k.endswith("}" + name):
            return v
    return default

def _find_application(manifest_root):
    for el in manifest_root.iter():
        if el.tag.endswith("application"):
            return el
    return None

def _iter_components(manifest_root, tag_suffix):
    for el in manifest_root.iter():
        if el.tag.endswith(tag_suffix):
            yield el

def _extract_intents_and_deeplinks(component_elem):
    intent_actions = []
    deep_links = []

    for ifilter in component_elem.iter():
        if not ifilter.tag.endswith("intent-filter"):
            continue

        for a_el in ifilter.iter():
            if a_el.tag.endswith("action"):
                name = _get_attr(a_el, "name")
                if name and name not in intent_actions:
                    intent_actions.append(name)

            if a_el.tag.endswith("data"):
                scheme = _get_attr(a_el, "scheme")
                host = _get_attr(a_el, "host")
                path = (
                    _get_attr(a_el, "path")
                    or _get_attr(a_el, "pathPrefix")
                    or _get_attr(a_el, "pathPattern")
                )
                mime = _get_attr(a_el, "mimeType")
                label = None

                if scheme and host:
                    label = f"{scheme}://{host}{path or ''}"
                elif scheme:
                    label = f"{scheme}://*"
                elif mime:
                    label = f"MIME {mime}"

                if label and label not in deep_links:
                    deep_links.append(label)

    deep_links_fmt = [f"DEEP_LINK {dl}" for dl in deep_links]
    return intent_actions, deep_links_fmt, deep_links

def build_analysis(apk_obj):
    pkg = apk_obj.get_package()
    version_code = apk_obj.get_androidversion_code() or ""
    version_name = apk_obj.get_androidversion_name() or ""

    manifest = apk_obj.get_android_manifest_xml()

    app_el = _find_application(manifest)

    app_config = []

    # debuggable
    try:
        if hasattr(apk_obj, "is_debuggable") and apk_obj.is_debuggable():
            app_config.append({
                "level": "CRITICAL",
                "name": "debuggable=true",
                "description": (
                    "Application is debuggable. This allows JDWP attachment, "
                    "runtime tampering and easier memory inspection."
                ),
                "hint": "Disable android:debuggable for release builds.",
            })
    except Exception:
        pass

    # allowBackup/usesCleartextTraffic
    if app_el is not None:
        allow_backup = _get_attr(app_el, "allowBackup")
        if allow_backup is None or allow_backup.lower() == "true":
          app_config.append({
                "level": "HIGH",
                "name": f"allowBackup={allow_backup or 'true (default)'}",
                "description": (
                    "Backups are enabled. App data can be extracted via "
                    "local backup (adb backup) on devices with USB debugging."
                ),
                "hint": "Set android:allowBackup=\"false\" for production builds.",
            })

        uses_cleartext = _get_attr(app_el, "usesCleartextTraffic")
        if uses_cleartext and uses_cleartext.lower() == "true":
            app_config.append({
                "level": "HIGH",
                "name": "usesCleartextTraffic=true",
                "description": (
                    "Cleartext HTTP traffic is explicitly allowed. This can be "
                    "abused for interception/tampering on untrusted networks."
                ),
                "hint": (
                    "Disable cleartext traffic or restrict it only to specific "
                    "domains via networkSecurityConfig."
                ),
            })

    components = []

    def handle_component(tag_suffix, ctype):
        for el in _iter_components(manifest, tag_suffix):
            name = _get_attr(el, "name")
            if not name:
                continue

            if name.startswith("."):
                name = f"{pkg}{name}"

            exported_val = _get_attr(el, "exported")
            exported = False
            if exported_val is not None:
                exported = exported_val.lower() == "true"

            permission = _get_attr(el, "permission")

            authority = None
            grant_uri_permissions = None
            if ctype == "provider":
                authority = _get_attr(el, "authorities")
                grant_uri_permissions_val = _get_attr(el, "grantUriPermissions")
                grant_uri_permissions = (
                    grant_uri_permissions_val is not None
                    and grant_uri_permissions_val.lower() == "true"
                )

            intent_actions, deep_links_fmt, deep_links_raw = _extract_intents_and_deeplinks(el)

            commands = []
            if ctype == "activity":
                commands.append(f"adb shell am start -n {pkg}/{name}")
            elif ctype == "service":
                commands.append(f"adb shell am startservice -n {pkg}/{name}")
            elif ctype == "receiver":
                commands.append(f"adb shell am broadcast -n {pkg}/{name}")
            elif ctype == "provider" and authority:
                commands.append(f"adb shell content query --uri content://{authority}/")

            for url in deep_links_raw:
                if "://" in url:
                    commands.append(
                        f'adb shell am start -a android.intent.action.VIEW -d "{url}" {pkg}'
                    )

            components.append({
                "type": ctype,
                "name": name,
                "exported": exported,
                "unprotectedExported": bool(exported and not permission),
                "permission": permission,
                "authority": authority,
                "grantUriPermissions": grant_uri_permissions,
                "intentActions": intent_actions,
                "deepLinks": deep_links_fmt,
                "commands": commands,
            })

    handle_component("activity", "activity")
    handle_component("service", "service")
    handle_component("receiver", "receiver")
    handle_component("provider", "provider")

    total_components = len(components)
    exported_components = sum(1 for c in components if c["exported"])
    unprotected_exported = sum(1 for c in components if c["unprotectedExported"])

    return {
        "packageName": pkg,
        "versionCode": str(version_code),
        "versionName": str(version_name),
        "appConfig": app_config,
        "components": components,
        "totalComponents": total_components,
        "exportedComponents": exported_components,
        "unprotectedExported": unprotected_exported,
    }

# paths
@app.get("/")
async def root():
    # index.html
    return FileResponse("index.html", media_type="text/html")


@app.post("/analyze-apk")
async def analyze_apk(file: UploadFile = File(...)):
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".apk")
    os.close(tmp_fd)
    try:
        with open(tmp_path, "wb") as f:
            f.write(await file.read())

        apk_obj, d, dx = AnalyzeAPK(tmp_path)
        result = build_analysis(apk_obj)
        return result
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
