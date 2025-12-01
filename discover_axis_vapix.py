#!/usr/bin/env python3
"""
Subnet scan Axis devices, list ACAP apps + status, and show app settings
by doing a full Param API dump per camera and filtering by app tokens.

Axis OS 12.x note:
- vaconfig/app config API removed, list.cgi does NOT expose settings.
- Settings live in param.cgi; full dump + filter is most reliable.

Requires: pip install requests
Optional: pip install tqdm
"""

import argparse
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
import re

import requests
requests.packages.urllib3.disable_warnings()

try:
    from tqdm import tqdm
except Exception:
    tqdm = None


# -------------------- VAPIX calls --------------------

def vapix_basic_device_info(ip, username=None, password=None, https=False, timeout=3.0):
    scheme = "https" if https else "http"
    url = f"{scheme}://{ip}/axis-cgi/basicdeviceinfo.cgi"

    session = requests.Session()
    session.verify = False
    if username and password:
        session.auth = (username, password)

    payload_unrestricted = {
        "apiVersion": "1.2",
        "context": "axis-discovery",
        "method": "getAllUnrestrictedProperties"
    }
    payload_all = {
        "apiVersion": "1.0",
        "context": "axis-discovery",
        "method": "getAllProperties"
    }

    try:
        r = session.post(url, json=payload_unrestricted, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        props = data.get("data", {}).get("propertyList", {})
        if props:
            return props
    except Exception:
        pass

    if username and password:
        try:
            r = session.post(url, json=payload_all, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            props = data.get("data", {}).get("propertyList", {})
            if props:
                return props
        except Exception:
            pass

    return {}


def vapix_list_apps(ip, username, password, https=False, timeout=3.0):
    """
    POST /axis-cgi/applications/list.cgi
    Returns list of dicts: {name, nice_name, vendor, version, status}
    """
    if not (username and password):
        return None

    scheme = "https" if https else "http"
    url = f"{scheme}://{ip}/axis-cgi/applications/list.cgi"

    try:
        r = requests.post(url, auth=(username, password), verify=False, timeout=timeout)
        r.raise_for_status()
        root = ET.fromstring(r.text)

        apps = []
        for app in root.findall(".//application"):
            apps.append({
                "name": app.attrib.get("Name", ""),
                "nice_name": app.attrib.get("NiceName", "") or app.attrib.get("Name", ""),
                "vendor": app.attrib.get("Vendor", ""),
                "version": app.attrib.get("Version", ""),
                "status": app.attrib.get("Status", ""),
                "params": {},
            })
        return apps
    except Exception:
        return []


def vapix_full_param_dump(ip, username, password, https=False, timeout=6.0):
    """
    GET /axis-cgi/param.cgi?action=list   (NO group)
    Returns raw parameter text.
    Heavy but most reliable on OS 12.x for app settings.
    """
    if not (username and password):
        return ""

    scheme = "https" if https else "http"
    url = f"{scheme}://{ip}/axis-cgi/param.cgi"

    try:
        r = requests.get(
            url,
            params={"action": "list"},
            auth=(username, password),
            verify=False,
            timeout=timeout
        )
        r.raise_for_status()
        return r.text or ""
    except Exception:
        return ""


def discover_app_params_from_full_dump(app, full_text):
    """
    Filter full param dump for entries containing app tokens.
    Returns dict of {short_param_name: value}.
    Shortens keys by removing leading 'root.<AppToken>.' when present.
    """
    params = {}

    def token(s):
        return re.sub(r"[^A-Za-z0-9_]", "", (s or "")).lower()

    tokens = list(filter(None, [
        token(app.get("name")),
        token(app.get("nice_name")),
        token(app.get("vendor")),
    ]))

    if not tokens or not full_text:
        return params

    for line in full_text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        k_low = k.lower()

        if any(t in k_low for t in tokens):
            short_k = k

            # Strip "root.<token>." prefix if it matches any token
            for t in tokens:
                prefix = f"root.{t}."
                if k_low.startswith(prefix):
                    short_k = k[len(prefix):]
                    break

            # Also handle "root.<Token>.<Token>." variants (seen sometimes)
            for t in tokens:
                double_prefix = f"root.{t}.{t}."
                if k_low.startswith(double_prefix):
                    short_k = k[len(double_prefix):]
                    break

            params[short_k] = v

    return params


# -------------------- Scan helpers --------------------

def tcp_port_open(ip, port, timeout=0.4):
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return True
    except Exception:
        return False


def is_axis_props(props: dict):
    if not props:
        return False
    if props.get("Brand", "").upper() == "AXIS":
        return True
    if props.get("SerialNumber") or props.get("ProdFullName") or props.get("ProdNbr"):
        return True
    return False


def extract_os_version(props: dict):
    for k in ("OSVersion", "FirmwareVersion", "SWVersion", "Version"):
        v = props.get(k)
        if v:
            return str(v).strip()
    return ""


def probe_ip_for_axis(ip, username=None, password=None, timeout=3.0):
    ip_str = str(ip)

    if tcp_port_open(ip_str, 80):
        props = vapix_basic_device_info(ip_str, username, password, https=False, timeout=timeout)
        if is_axis_props(props):
            return ip_str, props, False

    if tcp_port_open(ip_str, 443):
        props = vapix_basic_device_info(ip_str, username, password, https=True, timeout=timeout)
        if is_axis_props(props):
            return ip_str, props, True

    return None


def format_device(ip, props, https_used, apps, hostname):
    return {
        "ip": ip,
        "hostname": hostname,
        "device_type": props.get("ProdType", "") or "",
        "model": props.get("ProdNbr", "") or props.get("ProdShortName", "") or "",
        "name": props.get("ProdFullName", "") or "",
        "serial": props.get("SerialNumber", "") or "",
        "os_version": extract_os_version(props),
        "apps": apps,
        "scheme": "https" if https_used else "http",
    }

def vapix_get_hostname(ip, username, password, https=False, timeout=3.0):
    """
    Fallback hostname read via param.cgi.
    Tries a few common keys.
    Returns "" if not found.
    """
    if not (username and password):
        return ""

    scheme = "https" if https else "http"
    url = f"{scheme}://{ip}/axis-cgi/param.cgi"

    keys_to_try = [
        "root.Network.HostName",
        "root.Host.Name",
        "root.System.HostName",
    ]

    for key in keys_to_try:
        try:
            r = requests.get(
                url,
                params={"action": "list", "group": key},
                auth=(username, password),
                verify=False,
                timeout=timeout
            )
            r.raise_for_status()
            for line in r.text.splitlines():
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip()
        except Exception:
            continue

    return ""


def extract_hostname(props: dict):
    """
    Try basicdeviceinfo keys first.
    """
    for k in ("HostName", "Host", "SystemName", "DeviceName"):
        v = props.get(k)
        if v:
            return str(v).strip()
    return ""

# -------------------- Output --------------------

def print_devices(devices):
    # --- Per-device detail FIRST ---
    for d in devices:
        hn = f"{d['hostname']} " if d.get("hostname") else ""
        print(f"== {hn}{d['ip']}  ({d['model']}) ==")
        apps = d["apps"]
        if apps is None:
            print("  Apps: auth not provided, skipping list/settings\n")
            continue
        if apps == []:
            print("  Apps: none installed or insufficient rights / API not available\n")
            continue

        for a in apps:
            nice = a["nice_name"] or a["name"]
            status = a["status"] or "Unknown"
            vendor = f" [{a['vendor']}]" if a["vendor"] else ""
            ver = f" v{a['version']}" if a["version"] else ""
            print(f"  - {nice}{vendor}{ver} -> {status}")

            if a["params"]:
                items = list(a["params"].items())
                print("      params:")
                for k, v in items:
                    print(f"        - {k} = {v}")
            else:
                print("      params: (no matching keys found in param dump)")
        print()

    # --- Summary table LAST ---
    headers = ["HostName", "IP", "Type", "Model", "Name", "Serial", "OS Version", "Apps"]
    widths = {h: len(h) for h in headers}

    def apps_summary(apps):
        if apps is None:
            return "auth not provided"
        if apps == []:
            return "none / no access"
        running = sum(1 for a in apps if a["status"].lower() == "running")
        return f"{len(apps)} installed ({running} running)"

    for d in devices:
        widths["IP"] = max(widths["IP"], len(d["ip"]))
        widths["Type"] = max(widths["Type"], len(d["device_type"]))
        widths["Model"] = max(widths["Model"], len(d["model"]))
        widths["Name"] = max(widths["Name"], len(d["name"]))
        widths["Serial"] = max(widths["Serial"], len(d["serial"]))
        widths["OS Version"] = max(widths["OS Version"], len(d["os_version"]))
        widths["Apps"] = max(widths["Apps"], len(apps_summary(d["apps"])))

    def row(vals):
        return " | ".join(v.ljust(widths[h]) for v, h in zip(vals, headers))

    print(row(headers))
    print("-+-".join("-" * widths[h] for h in headers))
    for d in devices:
        print(row([
            d.get("hostname",""),
            d["ip"],
            d["device_type"],
            d["model"],
            d["name"],
            d["serial"],
            d["os_version"],
            apps_summary(d["apps"]),
        ]))

    print(f"\nFound {len(devices)} Axis device(s).")



# -------------------- Main --------------------

def main():
    ap = argparse.ArgumentParser(description="Discover Axis devices + apps + settings via full param scan")
    ap.add_argument("--subnet", type=str, default="192.168.1.0/24")
    ap.add_argument("--workers", type=int, default=128)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--param-timeout", type=float, default=8.0,
                    help="Timeout for full param dump per camera")
    ap.add_argument("--user", type=str, default=None)
    ap.add_argument("--passw", type=str, default=None)
    args = ap.parse_args()

    net = ipaddress.ip_network(args.subnet, strict=False)
    hosts = list(net.hosts())
    found = []

    print(f"Scanning subnet {net} for Axis devices (VAPIX)...")

    pbar = tqdm(total=len(hosts), desc="Probing hosts", unit="ip") if tqdm else None

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(probe_ip_for_axis, ip, args.user, args.passw, args.timeout): ip
            for ip in hosts
        }

        for fut in as_completed(futures):
            if pbar:
                pbar.update(1)

            res = fut.result()
            if not res:
                continue

            ip_str, props, https_used = res

            apps = vapix_list_apps(ip_str, args.user, args.passw, https=https_used, timeout=args.timeout)

            # Full param dump ONCE per camera, then filter per app
            if apps not in (None, []):
                full_params_text = vapix_full_param_dump(
                    ip_str, args.user, args.passw,
                    https=https_used, timeout=args.param_timeout
                )
                for app in apps:
                    app["params"] = discover_app_params_from_full_dump(app, full_params_text)
            hostname = extract_hostname(props)
            if not hostname:
                hostname = vapix_get_hostname(
                    ip_str, args.user, args.passw,
                    https=https_used, timeout=args.timeout
                )

            found.append(format_device(ip_str, props, https_used, apps, hostname))

    if pbar:
        pbar.close()

    if not found:
        print("No Axis devices found.")
        return

    uniq = {d["ip"]: d for d in found}
    devices = list(uniq.values())

    print_devices(devices)


if __name__ == "__main__":
    main()
