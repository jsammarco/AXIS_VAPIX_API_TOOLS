#!/usr/bin/env python3
"""
AXIS Dynamic Overlay API helper.

Provides CLI and interactive menu for calling /axis-cgi/dynamicoverlay.cgi
methods (addImage, addText, list, remove, setImage, setText,
getSupportedVersions, getOverlayCapabilities), /axis-cgi/dynamicoverlay.cgi
actions for dynamic text (dtext-gettext, dtext-settext), and
/axis-cgi/uploadoverlayimage.cgi methods (uploadOverlayImage, listImages,
deleteImage).

Text overlays accept Axis overlay modifiers and dynamic text tokens such as
`#D1`, so you can combine device-provided variables with slot-based text that
is updated separately through the camera's dynamic text endpoint
(/axis-cgi/dynamicoverlay/dynamicoverlay.cgi?action=setDynamicText&slot=<n>&text=<value>).
Image overlays can be uploaded directly via `uploadOverlayImage` before being
referenced in `addImage` or `setImage`.

Examples:
  python overlay.py --ip 192.168.0.10 --user root --passw pass \
      --method addText --param text="Hello" --param position_x=100 --param position_y=100

If no method/params are supplied, an interactive console menu is shown.
"""

import argparse
import json
import mimetypes
import socket
from getpass import getpass
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlencode

import requests
from requests.auth import HTTPDigestAuth
from requests.exceptions import RequestException

requests.packages.urllib3.disable_warnings()


SUPPORTED_METHODS = [
    "addImage",
    "addText",
    "dtext-gettext",
    "dtext-settext",
    "getSupportedVersions",
    "list",
    "listImages",
    "remove",
    "setImage",
    "setText",
    "getOverlayCapabilities",
    "uploadOverlayImage",
    "deleteImage",
]

IMAGE_METHODS = {"uploadOverlayImage", "listImages", "deleteImage"}
UPLOAD_IMAGE_METHODS = {"uploadOverlayImage"}
DYNAMIC_TEXT_METHODS = {"dtext-settext", "dtext-gettext"}


def dynamic_action_from_method(method: str) -> str:
    if method == "dtext-settext":
        return "settext"
    if method == "dtext-gettext":
        return "gettext"
    return method


def tcp_port_open(ip: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def detect_scheme(ip: str, prefer_https: bool = True) -> Optional[str]:
    http_open = tcp_port_open(ip, 80)
    https_open = tcp_port_open(ip, 443)

    if prefer_https and https_open:
        return "https"
    if http_open:
        return "http"
    if https_open:
        return "https"
    return None


def post_with_anyauth(url: str, *, username: Optional[str], password: Optional[str],
                      timeout: float = 10.0, json_body: Dict[str, object] = None) -> requests.Response:
    session = requests.Session()
    session.verify = False
    session.auth = (username, password) if username and password else None

    response = session.post(url, json=json_body, timeout=timeout)
    if response.status_code != 401:
        return response

    digest_session = requests.Session()
    digest_session.verify = False
    digest_session.auth = HTTPDigestAuth(username, password) if username and password else None
    return digest_session.post(url, json=json_body, timeout=timeout)


def get_with_anyauth(url: str, *, username: Optional[str], password: Optional[str],
                     timeout: float = 10.0, params: Optional[Dict[str, object]] = None) -> requests.Response:
    session = requests.Session()
    session.verify = False
    session.auth = (username, password) if username and password else None

    response = session.get(url, params=params, timeout=timeout)
    if response.status_code != 401:
        return response

    digest_session = requests.Session()
    digest_session.verify = False
    digest_session.auth = HTTPDigestAuth(username, password) if username and password else None
    return digest_session.get(url, params=params, timeout=timeout)


def parse_param_pairs(pairs: List[str]) -> Dict[str, object]:
    params: Dict[str, object] = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"Invalid param '{pair}', expected key=value")
        key, value = pair.split("=", 1)
        params[key] = coerce_value(value)
    return params


def coerce_value(raw: str) -> object:
    lowered = raw.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        if raw.startswith("0") and len(raw) > 1:
            raise ValueError
        return int(raw)
    except ValueError:
        try:
            return float(raw)
        except ValueError:
            pass
    try:
        return json.loads(raw)
    except Exception:
        return raw


def send_overlay_request(ip: str, method: str, *, username: Optional[str], password: Optional[str],
                         version: str = "1.0", params: Optional[Dict[str, object]] = None,
                         context: Optional[str] = None, scheme: Optional[str] = None,
                         payload: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    if scheme is None:
        scheme = detect_scheme(ip) or "http"

    url = f"{scheme}://{ip}/axis-cgi/dynamicoverlay/dynamicoverlay.cgi"
    if payload is None:
        payload = create_payload(method, version=version, params=params, context=context)

    try:
        resp = post_with_anyauth(url, username=username, password=password, json_body=payload, timeout=15.0)
    except RequestException as exc:
        return {"error": str(exc)}

    try:
        return resp.json()
    except ValueError:
        return {"status_code": resp.status_code, "text": resp.text}


def send_overlay_image_request(ip: str, method: str, *, username: Optional[str], password: Optional[str],
                              version: str = "1.0", params: Optional[Dict[str, object]] = None,
                              context: Optional[str] = None, scheme: Optional[str] = None,
                              payload: Optional[Dict[str, object]] = None,
                              image_path: Optional[str] = None) -> Dict[str, object]:
    if scheme is None:
        scheme = detect_scheme(ip) or "http"

    url = f"{scheme}://{ip}/axis-cgi/uploadoverlayimage.cgi"
    if payload is None:
        payload = create_payload(method, version=version, params=params, context=context)

    if method in UPLOAD_IMAGE_METHODS:
        if not image_path:
            return {"error": "Image file path is required for uploadOverlayImage"}

        try:
            image_bytes = Path(image_path).read_bytes()
        except OSError as exc:
            return {"error": f"Unable to read image file: {exc}"}

        mime_type, _ = mimetypes.guess_type(image_path)
        mime_type = mime_type or "application/octet-stream"

        def post_multipart(auth_object):
            session = requests.Session()
            session.verify = False
            session.auth = auth_object
            files = {
                "json": ("request.json", json.dumps(payload), "application/json"),
                "image": (Path(image_path).name, image_bytes, mime_type),
            }
            return session.post(url, files=files, timeout=15.0)

        try:
            resp = post_multipart((username, password) if username and password else None)
            if resp.status_code == 401:
                digest_auth = HTTPDigestAuth(username, password) if username and password else None
                resp = post_multipart(digest_auth)
        except RequestException as exc:
            return {"error": str(exc)}
    else:
        try:
            resp = post_with_anyauth(url, username=username, password=password, json_body=payload, timeout=15.0)
        except RequestException as exc:
            return {"error": str(exc)}

    try:
        return resp.json()
    except ValueError:
        return {"status_code": resp.status_code, "text": resp.text}


def send_dynamic_text_request(ip: str, action: str, *, username: Optional[str], password: Optional[str],
                              params: Optional[Dict[str, object]] = None, scheme: Optional[str] = None) -> Dict[str, object]:
    if scheme is None:
        scheme = detect_scheme(ip) or "http"

    url = f"{scheme}://{ip}/axis-cgi/dynamicoverlay.cgi"
    params = dict(params or {})
    params.setdefault("action", action)

    try:
        resp = get_with_anyauth(url, username=username, password=password, params=params, timeout=15.0)
    except RequestException as exc:
        return {"error": str(exc)}

    try:
        return resp.json()
    except ValueError:
        return {"status_code": resp.status_code, "text": resp.text}


def print_response(response: Dict[str, object], *, json_only: bool = False) -> None:
    if json_only:
        print(json.dumps(response, ensure_ascii=False))
        return

    print("\n--- Response ---")
    print(json.dumps(response, indent=2, ensure_ascii=False))


def create_payload(method: str, *, version: str = "1.0", params: Optional[Dict[str, object]] = None,
                   context: Optional[str] = None) -> Dict[str, object]:
    if method == "getSupportedVersions":
        payload: Dict[str, object] = {"method": method}
    else:
        payload = {
            "method": method,
            "apiVersion": version,
            "params": params or {},
        }

    if context:
        payload["context"] = context

    return payload


def prompt_value(prompt: str, *, required: bool = False, default: Optional[str] = None) -> Optional[object]:
    suffix = f" (default {default})" if default is not None else ""
    while True:
        raw = input(f"{prompt}{suffix}: ").strip()
        if raw:
            return coerce_value(raw)
        if default is not None:
            return coerce_value(default)
        if not required:
            return None
        print("This field is required.")


def normalize_overlay_text(text_value: object) -> object:
    if not isinstance(text_value, str):
        return text_value

    normalized = text_value.replace("\\n", "%0A")
    normalized = normalized.replace("\r\n", "%0A").replace("\n", "%0A")
    return normalized


def apply_text_normalization(method: str, params: Dict[str, object]) -> Dict[str, object]:
    if method not in {"addText", "setText", "dtext-settext"}:
        return params

    if "text" not in params:
        return params

    normalized_text = normalize_overlay_text(params["text"])
    if normalized_text == params["text"]:
        return params

    updated = dict(params)
    updated["text"] = normalized_text
    return updated


def prompt_text_params(identity_required: bool = False) -> Dict[str, object]:
    print("\nProvide text overlay details:")
    params: Dict[str, object] = {}
    if identity_required:
        identity = prompt_value("Existing overlay identity (integer)", required=True)
        params["identity"] = identity

    camera = prompt_value("Camera number", default="1")
    if camera is not None:
        params["camera"] = camera

    print("New lines: type %0A or \\n (\\n will be converted to %0A for you)")
    text_value = prompt_value("Overlay text", required=True)
    params["text"] = text_value

    print("Select position (examples: topLeft, bottomRight, custom)")
    position = prompt_value("Position", default="topLeft")
    if position:
        params["position"] = position

    font_size = prompt_value("Font size (leave blank to let camera choose)")
    if font_size is not None:
        params["fontSize"] = font_size

    text_color = prompt_value("Text color", default="white")
    if text_color:
        params["textColor"] = text_color

    bg_color = prompt_value("Background color (leave blank for transparent)")
    if bg_color:
        params["backgroundColor"] = bg_color

    if position and str(position).lower() == "custom":
        pos_x = prompt_value("Custom position X")
        pos_y = prompt_value("Custom position Y")
        if pos_x is not None:
            params["position_x"] = pos_x
        if pos_y is not None:
            params["position_y"] = pos_y

    return params


def prompt_dynamic_settext_params() -> Dict[str, object]:
    print("\nUpdate dynamic text slot:")
    params: Dict[str, object] = {}

    text_index = prompt_value("Text slot index", required=True)
    params["text_index"] = text_index

    print("New lines: type %0A or \\n (\\n will be converted to %0A for you)")
    text_value = prompt_value("Dynamic text value", required=True)
    params["text"] = text_value

    return params


def prompt_dynamic_gettext_params() -> Dict[str, object]:
    print("\nRetrieve dynamic text slot:")
    params: Dict[str, object] = {}

    text_index = prompt_value("Text slot index", required=True)
    params["text_index"] = text_index

    return params


def prompt_add_image_params() -> Dict[str, object]:
    print("\nProvide image overlay details:")
    params: Dict[str, object] = {}

    camera = prompt_value("Camera number", default="1")
    if camera is not None:
        params["camera"] = camera

    overlay_path = prompt_value("Overlay image path", required=True)
    params["overlayPath"] = overlay_path

    position = prompt_value(
        "Position (topLeft, bottomRight, or 'custom' for coordinates)",
        default="topLeft",
    )
    if position:
        if isinstance(position, str) and position.lower() == "custom":
            pos_x = prompt_value("Custom position X (-1.0 to 1.0)", required=True)
            pos_y = prompt_value("Custom position Y (-1.0 to 1.0)", required=True)
            params["position"] = [pos_x, pos_y]
        else:
            params["position"] = position

    return params


def prompt_set_image_params() -> Dict[str, object]:
    print("\nUpdate image overlay parameters:")
    params: Dict[str, object] = {}

    identity = prompt_value("Existing overlay identity (integer)", required=True)
    params["identity"] = identity

    overlay_path = prompt_value("Overlay image path (leave blank to keep current)")
    if overlay_path:
        params["overlayPath"] = overlay_path

    position = prompt_value(
        "Position (topLeft, bottomRight, custom, or leave blank to keep)",
    )
    if position:
        if isinstance(position, str) and position.lower() == "custom":
            pos_x = prompt_value("Custom position X (-1.0 to 1.0)", required=True)
            pos_y = prompt_value("Custom position Y (-1.0 to 1.0)", required=True)
            params["position"] = [pos_x, pos_y]
        else:
            params["position"] = position

    return params


def prompt_remove_params() -> Dict[str, object]:
    print("\nProvide overlay details to remove:")
    params: Dict[str, object] = {}
    identity = prompt_value("Overlay identity", required=True)
    params["identity"] = identity

    return params


def interactive_menu(args: argparse.Namespace) -> None:
    print("Dynamic Overlay API interactive mode")
    if not args.ip:
        args.ip = input("Camera IP or hostname: ").strip()
    if not args.user:
        args.user = input("Username (leave blank for none): ").strip() or None
    if args.passw is None:
        args.passw = getpass("Password (leave blank for none): ") or None

    print("\nSelect method:")
    for idx, m in enumerate(SUPPORTED_METHODS, start=1):
        print(f"  {idx}) {m}")
    choice = input("Enter number or method name: ").strip()
    if choice.isdigit():
        choice_idx = int(choice) - 1
        if 0 <= choice_idx < len(SUPPORTED_METHODS):
            args.method = SUPPORTED_METHODS[choice_idx]
        else:
            print("Invalid choice")
            return
    else:
        args.method = choice

    args.version = args.version or input("API version (default 1.0): ").strip() or "1.0"
    if args.method not in DYNAMIC_TEXT_METHODS and args.context is None:
        args.context = input("Context value to echo in responses (optional): ").strip() or None

    params: Dict[str, object] = {}
    if args.method == "addImage":
        params = prompt_add_image_params()
    elif args.method == "addText":
        params = prompt_text_params()
    elif args.method == "setText":
        params = prompt_text_params(identity_required=True)
    elif args.method == "dtext-settext":
        params = prompt_dynamic_settext_params()
    elif args.method == "dtext-gettext":
        params = prompt_dynamic_gettext_params()
    elif args.method == "remove":
        params = prompt_remove_params()
    elif args.method == "setImage":
        params = prompt_set_image_params()
    elif args.method == "deleteImage":
        path = prompt_value("Path to image to delete", required=True)
        if path is not None:
            params["path"] = path
    elif args.method == "list":
        params = {}
    elif args.method == "listImages":
        params = {}
    elif args.method == "getSupportedVersions":
        params = {}
    elif args.method == "uploadOverlayImage":
        args.image_file = input("Path to image file: ").strip()
        scale_choice = prompt_value("Scale to resolution?", default="true")
        if scale_choice is not None:
            params["scaleToResolution"] = scale_choice
        alpha = prompt_value("Overlay alpha (hex, leave blank for default)")
        if alpha:
            params["alpha"] = alpha
        args.params = params
        perform_call(args)
        return
    else:
        print("\nEnter params as key=value (blank line to finish):")
        while True:
            line = input("> ").strip()
            if not line:
                break
            try:
                key, value = line.split("=", 1)
                params[key] = coerce_value(value)
            except ValueError:
                print("Invalid entry, use key=value")

    args.params = params
    perform_call(args)


def build_curl_command(url: str, payload: Dict[str, object], username: Optional[str], password: Optional[str]) -> str:
    auth_part = ""
    if username is not None:
        auth_part = f'-u "{username}:{password or ""}" '

    raw_data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    escaped_data = raw_data.replace("\"", r"\\\"")
    return (
        "curl --anyauth "
        f"{auth_part}-H \"Content-Type: application/json\" "
        f"--data \"{escaped_data}\" {url} -k"
    )


def build_dynamic_curl_command(url: str, params: Dict[str, object], username: Optional[str], password: Optional[str]) -> str:
    auth_part = ""
    if username is not None:
        auth_part = f'-u "{username}:{password or ""}" '

    encoded_params = urlencode(params, doseq=True)
    return f"curl --anyauth {auth_part}{url}?{encoded_params} -k"


def perform_call(args: argparse.Namespace) -> None:
    params = args.params or {}
    params = apply_text_normalization(args.method, params)

    if args.method in IMAGE_METHODS:
        perform_image_call(args, params)
        return
    if args.method in DYNAMIC_TEXT_METHODS:
        perform_dynamic_text_call(args, params)
        return

    scheme = args.scheme or detect_scheme(args.ip) or "http"
    url = f"{scheme}://{args.ip}/axis-cgi/dynamicoverlay/dynamicoverlay.cgi"
    payload = create_payload(args.method, version=args.version, params=params, context=args.context)

    if not args.json_only:
        print("\n--- Request ---")
        print(json.dumps(payload, indent=2, ensure_ascii=False))

        print("\nEquivalent curl command:")
        print(build_curl_command(url, payload, args.user, args.passw))

    response = send_overlay_request(
        args.ip,
        args.method,
        username=args.user,
        password=args.passw,
        version=args.version,
        params=params,
        context=args.context,
        scheme=scheme,
        payload=payload,
    )
    print_response(response, json_only=args.json_only)


def build_upload_curl_command(url: str, payload: Dict[str, object], username: Optional[str], password: Optional[str],
                              image_path: str) -> str:
    auth_part = ""
    if username is not None:
        auth_part = f'-u "{username}:{password or ""}" '

    raw_data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    escaped_data = raw_data.replace("\"", r"\\\"")
    return (
        "curl --anyauth "
        f"{auth_part}-F \"json={escaped_data}\" "
        f"-F \"image=@{image_path}\" {url} -k"
    )


def perform_image_call(args: argparse.Namespace, params: Dict[str, object]) -> None:
    scheme = args.scheme or detect_scheme(args.ip) or "http"
    url = f"{scheme}://{args.ip}/axis-cgi/uploadoverlayimage.cgi"
    payload = create_payload(args.method, version=args.version, params=params, context=args.context)

    if not args.json_only:
        print("\n--- Request ---")
        print(json.dumps(payload, indent=2, ensure_ascii=False))

        print("\nEquivalent curl command:")
        if args.method in UPLOAD_IMAGE_METHODS and args.image_file:
            print(build_upload_curl_command(url, payload, args.user, args.passw, args.image_file))
        else:
            print(build_curl_command(url, payload, args.user, args.passw))

    response = send_overlay_image_request(
        args.ip,
        args.method,
        username=args.user,
        password=args.passw,
        version=args.version,
        params=params,
        context=args.context,
        scheme=scheme,
        payload=payload,
        image_path=args.image_file,
    )
    print_response(response, json_only=args.json_only)


def perform_dynamic_text_call(args: argparse.Namespace, params: Dict[str, object]) -> None:
    scheme = args.scheme or detect_scheme(args.ip) or "http"
    url = f"{scheme}://{args.ip}/axis-cgi/dynamicoverlay.cgi"
    params = dict(params)
    action = dynamic_action_from_method(args.method)
    params.setdefault("action", action)

    if not args.json_only:
        print("\n--- Request ---")
        print(json.dumps({"action": params.get("action"), **{k: v for k, v in params.items() if k != "action"}}, indent=2, ensure_ascii=False))

        print("\nEquivalent curl command:")
        print(build_dynamic_curl_command(url, params, args.user, args.passw))

    response = send_dynamic_text_request(
        args.ip,
        action,
        username=args.user,
        password=args.passw,
        params=params,
        scheme=scheme,
    )
    print_response(response, json_only=args.json_only)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Interact with Axis Dynamic Overlay API")
    parser.add_argument("--ip", help="Camera IP or hostname")
    parser.add_argument("--user", dest="user", help="Username")
    parser.add_argument("--passw", dest="passw", help="Password")
    parser.add_argument("--scheme", choices=["http", "https"], help="Force HTTP or HTTPS (auto-detect default)")
    parser.add_argument("--method", choices=SUPPORTED_METHODS, help="Overlay API method to call")
    parser.add_argument("--version", default="1.0", help="API version (default 1.0)")
    parser.add_argument("--context", help="Optional context string to echo back in responses")
    parser.add_argument("--json-only", action="store_true", help="Only output JSON responses (suppress request and curl previews)")
    parser.add_argument(
        "--param",
        action="append",
        dest="param_pairs",
        default=[],
        help="Parameter key=value (repeat for multiple)",
    )
    parser.add_argument("--image-file", dest="image_file", help="Image file path for uploadOverlayImage")
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.param_pairs:
        args.params = parse_param_pairs(args.param_pairs)
    else:
        args.params = {}

    if args.method in DYNAMIC_TEXT_METHODS:
        args.context = None

    if not args.method or not args.ip:
        interactive_menu(args)
        return

    perform_call(args)


if __name__ == "__main__":
    main()
