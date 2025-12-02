#!/usr/bin/env python3
"""
AXIS Dynamic Overlay API helper.

Provides CLI and interactive menu for calling /axis-cgi/dynamicoverlay.cgi
methods (addImage, addText, list, remove, setImage, setText,
getSupportedVersions, getOverlayCapabilities).

Examples:
  python overlay.py --ip 192.168.0.10 --user root --passw pass \
      --method addText --param text="Hello" --param position_x=100 --param position_y=100

If no method/params are supplied, an interactive console menu is shown.
"""

import argparse
import json
import socket
from getpass import getpass
from typing import Dict, List, Optional

import requests
from requests.auth import HTTPDigestAuth
from requests.exceptions import RequestException

requests.packages.urllib3.disable_warnings()


SUPPORTED_METHODS = [
    "addImage",
    "addText",
    "getSupportedVersions",
    "list",
    "remove",
    "setImage",
    "setText",
    "getOverlayCapabilities",
]


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
                         context: Optional[str] = None, scheme: Optional[str] = None) -> Dict[str, object]:
    if scheme is None:
        scheme = detect_scheme(ip) or "http"

    url = f"{scheme}://{ip}/axis-cgi/dynamicoverlay/dynamicoverlay.cgi"
    payload = {
        "method": method,
        "apiVersion": version,
        "params": params or {},
    }

    if context:
        payload["context"] = context

    try:
        resp = post_with_anyauth(url, username=username, password=password, json_body=payload, timeout=15.0)
    except RequestException as exc:
        return {"error": str(exc)}

    try:
        return resp.json()
    except ValueError:
        return {"status_code": resp.status_code, "text": resp.text}


def print_response(response: Dict[str, object]) -> None:
    print("\n--- Response ---")
    print(json.dumps(response, indent=2, ensure_ascii=False))


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


def prompt_additional_params(existing: Dict[str, object]) -> Dict[str, object]:
    print("\nEnter any additional params as key=value (blank line to finish):")
    params = dict(existing)
    while True:
        line = input("> ").strip()
        if not line:
            break
        try:
            key, value = line.split("=", 1)
        except ValueError:
            print("Invalid entry, use key=value")
            continue
        params[key] = coerce_value(value)
    return params


def prompt_text_params(identity_required: bool = False) -> Dict[str, object]:
    print("\nProvide text overlay details:")
    params: Dict[str, object] = {}
    if identity_required:
        identity = prompt_value("Existing overlay identity (integer)", required=True)
        params["identity"] = identity

    camera = prompt_value("Camera number", default="1")
    if camera is not None:
        params["camera"] = camera

    text_value = prompt_value("Overlay text (supports escape sequences like \\n)", required=True)
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
    args.context = args.context or input("Context value to echo in responses (optional): ").strip() or None

    params: Dict[str, object] = {}
    if args.method == "addText":
        params = prompt_text_params()
    elif args.method == "setText":
        params = prompt_text_params(identity_required=True)
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

    args.params = prompt_additional_params(params)
    perform_call(args)


def perform_call(args: argparse.Namespace) -> None:
    params = args.params or {}
    response = send_overlay_request(
        args.ip,
        args.method,
        username=args.user,
        password=args.passw,
        version=args.version,
        params=params,
        context=args.context,
        scheme=args.scheme,
    )
    print_response(response)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Interact with Axis Dynamic Overlay API")
    parser.add_argument("--ip", help="Camera IP or hostname")
    parser.add_argument("--user", dest="user", help="Username")
    parser.add_argument("--passw", dest="passw", help="Password")
    parser.add_argument("--scheme", choices=["http", "https"], help="Force HTTP or HTTPS (auto-detect default)")
    parser.add_argument("--method", choices=SUPPORTED_METHODS, help="Overlay API method to call")
    parser.add_argument("--version", default="1.0", help="API version (default 1.0)")
    parser.add_argument("--context", help="Optional context string to echo back in responses")
    parser.add_argument(
        "--param",
        action="append",
        dest="param_pairs",
        default=[],
        help="Parameter key=value (repeat for multiple)",
    )
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.param_pairs:
        args.params = parse_param_pairs(args.param_pairs)
    else:
        args.params = {}

    if not args.method or not args.ip:
        interactive_menu(args)
        return

    perform_call(args)


if __name__ == "__main__":
    main()
