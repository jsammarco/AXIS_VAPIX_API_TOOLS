#!/usr/bin/env python3
"""
ACAP update tool using AXIS VAPIX Application API.

Fixes vs previous version:
- Longer, separate timeouts for control calls (connect, read)
- Retries with backoff for control/upload
- Stop/remove timeouts are treated as non-fatal
- No exceptions escape worker threads

Per Axis docs:
- upload: POST /axis-cgi/applications/upload.cgi (multipart field "file")
- control: POST /axis-cgi/applications/control.cgi?action=<action>&package=<package>
- list: POST /axis-cgi/applications/list.cgi
- anyauth: try Basic first, retry Digest if 401

Requires: pip install requests tqdm
"""

import argparse
import ipaddress
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

import requests
from requests.auth import HTTPDigestAuth
from requests.exceptions import ReadTimeout, ConnectTimeout, RequestException

requests.packages.urllib3.disable_warnings()

try:
    from tqdm import tqdm
except Exception:
    tqdm = None


UPLOAD_ERRORS = {
    1:  "Invalid application package (not an Embedded Axis Package).",
    2:  "Verification failed (signature missing/invalid).",
    3:  "Package too large OR disk full.",
    5:  "Package not compatible with device (see system log).",
    10: "Unspecified error (see system log).",
    12: "Upload unavailable (another upload ongoing).",
    13: "Installation failed (user/group not allowed).",
    14: "Package already exists with different letter case.",
    15: "Operation timed out (check logs).",
    29: "Invalid manifest.json or package.conf.",
}

CONTROL_ERRORS = {
    1:  "Invalid application package/manifest.",
    4:  "Application not found.",
    6:  "Application already running.",
    7:  "Application not running.",
    9:  "Too many apps running (removed in OS 12.6).",
    10: "Unspecified error (see system log).",
    15: "Operation timed out (check logs).",
}


# -------------------- Port/scheme helpers --------------------

def tcp_port_open(ip, port, timeout=0.4):
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return True
    except Exception:
        return False


def detect_scheme(ip, prefer_https=True):
    http_open = tcp_port_open(ip, 80)
    https_open = tcp_port_open(ip, 443)

    if prefer_https and https_open:
        return "https"
    if http_open:
        return "http"
    if https_open:
        return "https"
    return None


# -------------------- Auth helpers (anyauth) --------------------

def _vapix_session(username=None, password=None, use_digest=False):
    s = requests.Session()
    s.verify = False
    if username and password:
        s.auth = HTTPDigestAuth(username, password) if use_digest else (username, password)
    return s


def _post_with_anyauth(url, *, params=None, files=None, data=None,
                       timeout=(5.0, 20.0), username=None, password=None,
                       headers=None):
    """
    curl --anyauth equivalent:
    try Basic first, if 401 retry Digest.
    timeout can be a float or (connect_timeout, read_timeout).
    """
    # Basic attempt
    s = _vapix_session(username, password, use_digest=False)
    r = s.post(
        url,
        params=params,
        files=files,
        data=data,
        headers=headers,
        timeout=timeout,
    )

    if r.status_code != 401:
        return r

    # Digest retry
    s = _vapix_session(username, password, use_digest=True)
    r2 = s.post(
        url,
        params=params,
        files=files,
        data=data,
        headers=headers,
        timeout=timeout,
    )
    return r2


def _post_with_retries(url, *, params=None, files=None, data=None,
                       timeout=(5.0, 20.0), username=None, password=None,
                       headers=None, retries=3, backoff=1.5):
    """
    Anyauth + retries for slow/busy cameras.
    """
    last_exc = None
    for i in range(retries):
        try:
            return _post_with_anyauth(
                url,
                params=params,
                files=files,
                data=data,
                timeout=timeout,
                headers=headers,
                username=username,
                password=password,
            )
        except (ReadTimeout, ConnectTimeout) as e:
            last_exc = e
            if i < retries - 1:
                time.sleep(backoff ** i)
                continue
            raise
        except RequestException as e:
            last_exc = e
            if i < retries - 1:
                time.sleep(backoff ** i)
                continue
            raise
    raise last_exc


def parse_axis_error(text):
    t = (text or "").strip()
    if t.upper().startswith("OK"):
        return None
    if "Error:" in t:
        try:
            code = int(t.split("Error:")[1].strip().split()[0])
            return code
        except Exception:
            return -1
    return -1


# -------------------- Application API calls --------------------

def vapix_app_control(ip, username, password, scheme,
                      action, package,
                      timeout=(5.0, 25.0), retries=3):
    """
    POST /axis-cgi/applications/control.cgi
    Longer read timeout because stop/start/remove can take time.
    """
    url = f"{scheme}://{ip}/axis-cgi/applications/control.cgi"
    params = {"action": action, "package": package}

    try:
        r = _post_with_retries(
            url, params=params, timeout=timeout,
            username=username, password=password, retries=retries
        )
    except ReadTimeout:
        # Camera might still perform the action; treat as soft-fail for stop/remove
        return False, "timeout waiting for response"
    except Exception as e:
        return False, f"request failed: {e}"

    if r.status_code != 200:
        return False, f"HTTP {r.status_code}: {r.text.strip()[:200]}"

    code = parse_axis_error(r.text)
    if code is None:
        return True, "OK"
    return False, f"Error: {code} ({CONTROL_ERRORS.get(code,'Unknown')})"


def vapix_app_upload(ip, username, password, scheme,
                     eap_path,
                     timeout=(5.0, 90.0), retries=2,
                     show_progress=False):
    """
    POST /axis-cgi/applications/upload.cgi
    Uploads can take a while; longer read timeout.
    """
    url = f"{scheme}://{ip}/axis-cgi/applications/upload.cgi"

    upload_bar = None

    class UploadProgressFile:
        def __init__(self, file_obj, bar=None):
            self._file = file_obj
            self._bar = bar

        def read(self, size=-1):
            data = self._file.read(size)
            if self._bar and data:
                self._bar.update(len(data))
            return data

        def __getattr__(self, name):
            return getattr(self._file, name)

    try:
        with open(eap_path, "rb") as f:
            file_obj = f
            if tqdm and show_progress:
                try:
                    total_size = os.path.getsize(eap_path)
                except OSError:
                    total_size = None
                upload_bar = tqdm(
                    total=total_size,
                    desc=f"{ip} upload",
                    unit="B",
                    unit_scale=True,
                    unit_divisor=1024,
                    leave=False,
                )
                file_obj = UploadProgressFile(f, upload_bar)

            files = {"file": (os.path.basename(eap_path), file_obj, "application/octet-stream")}
            r = _post_with_retries(
                url, files=files, timeout=timeout,
                username=username, password=password, retries=retries
            )
    except ReadTimeout:
        return False, "timeout waiting for upload response"
    except Exception as e:
        return False, f"upload request failed: {e}"
    finally:
        if upload_bar:
            upload_bar.close()

    if r.status_code != 200:
        return False, f"HTTP {r.status_code}: {r.text.strip()[:200]}"

    code = parse_axis_error(r.text)
    if code is None:
        return True, "OK"
    return False, f"Error: {code} ({UPLOAD_ERRORS.get(code,'Unknown')})"


def vapix_app_list(ip, username, password, scheme, timeout=(5.0, 15.0), retries=2):
    """
    POST /axis-cgi/applications/list.cgi
    """
    url = f"{scheme}://{ip}/axis-cgi/applications/list.cgi"

    r = _post_with_retries(
        url, timeout=timeout,
        username=username, password=password, retries=retries
    )

    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}")

    root = ET.fromstring(r.text)
    apps = []
    for app in root.findall(".//application"):
        apps.append({
            "name": app.attrib.get("Name", ""),
            "nice_name": app.attrib.get("NiceName", "") or app.attrib.get("Name", ""),
            "vendor": app.attrib.get("Vendor", ""),
            "version": app.attrib.get("Version", ""),
            "status": app.attrib.get("Status", ""),
        })
    return apps


# -------------------- Param config helpers --------------------

def load_param_updates(path):
    updates = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                raise ValueError(f"Invalid line (missing '='): {line!r}")
            key, value = stripped.split("=", 1)
            updates[key.strip()] = value.strip()
    if not updates:
        raise ValueError("No parameters found in config file")
    return updates


def vapix_param_update(ip, username, password, scheme, updates,
                       timeout=(5.0, 15.0), retries=2, usergroup=None):
    """
    POST /axis-cgi/param.cgi?action=update with provided parameters.
    """
    url = f"{scheme}://{ip}/axis-cgi/param.cgi"

    payload = {"action": "update"}
    if usergroup:
        payload["usergroup"] = usergroup
    payload.update(updates)

    try:
        r = _post_with_retries(
            url,
            data=payload,
            timeout=timeout,
            username=username,
            password=password,
            retries=retries,
        )
    except Exception as e:
        return False, f"request failed: {e}"

    if r.status_code != 200:
        return False, f"HTTP {r.status_code}: {r.text.strip()[:200]}"

    text = r.text.strip()
    code = parse_axis_error(text)
    if code is None:
        return True, "OK"

    if code == -1:
        return False, text[:200] or "unexpected response"

    return False, f"Error: {code}"


# -------------------- Update flow --------------------

def update_one_camera(ip, username, password, package, eap_path,
                      stop_first=True, prefer_https=True,
                      force_http=False, force_https=False,
                      param_updates=None, usergroup=None,
                      show_progress=False):

    step_bar = None
    step_total = 3 + (1 if stop_first else 0) + (1 if param_updates else 0)
    if tqdm and show_progress:
        step_bar = tqdm(
            total=step_total,
            desc=f"{ip} steps",
            leave=False,
            unit="step",
        )

    def update_step(label):
        if step_bar:
            step_bar.set_postfix_str(label, refresh=False)
            step_bar.update(1)
        elif show_progress:
            print(f"{ip}: {label}")

    try:
        if force_http:
            scheme = "http" if tcp_port_open(ip, 80) else None
        elif force_https:
            scheme = "https" if tcp_port_open(ip, 443) else None
        else:
            scheme = detect_scheme(ip, prefer_https=prefer_https)

        if not scheme:
            return ip, False, "no http/https on 80/443"

        # Light capability check
        try:
            vapix_app_list(ip, username, password, scheme)
        except Exception as e:
            return ip, False, f"applications/list.cgi unavailable ({e})"

        # Stop (optional, soft-fail ok)
        if stop_first:
            ok, msg = vapix_app_control(ip, username, password, scheme, "stop", package)
            update_step("stop")
            # don't fail run on stop timeout/error
            # print(f"{ip}: stop -> {ok}, {msg}")

        # Remove old (soft-fail ok)
        vapix_app_control(ip, username, password, scheme, "remove", package)
        update_step("remove")

        # Upload new (hard fail if not OK)
        ok, msg = vapix_app_upload(
            ip, username, password, scheme, eap_path, show_progress=show_progress
        )
        update_step("upload")
        if not ok:
            return ip, False, f"upload failed: {msg}"

        time.sleep(2)

        if param_updates:
            ok, msg = vapix_param_update(
                ip, username, password, scheme, param_updates, usergroup=usergroup
            )
            update_step("config")
            if not ok:
                return ip, False, f"config update failed: {msg}"

        # Start (hard fail if not OK)
        ok, msg = vapix_app_control(ip, username, password, scheme, "start", package)
        update_step("start")
        if not ok and "already running" not in msg.lower():
            return ip, False, f"start failed: {msg}"

        # Verify status
        try:
            apps = vapix_app_list(ip, username, password, scheme)
            status = next((a["status"] for a in apps if a["name"] == package), "unknown")
        except Exception:
            status = "unknown"

        return ip, True, f"updated, status={status}"
    finally:
        if step_bar:
            step_bar.close()


# -------------------- Subnet targets --------------------

def subnet_targets(subnet_cidr):
    net = ipaddress.ip_network(subnet_cidr, strict=False)
    return [str(h) for h in net.hosts()]


# -------------------- Main --------------------

def main():
    ap = argparse.ArgumentParser(description="Update AXIS ACAP app via VAPIX Application API")
    ap.add_argument("--ip", help="Single camera IP. If omitted, subnet mode is used.")
    ap.add_argument("--subnet", help="CIDR subnet to update, e.g. 192.168.1.0/24")
    ap.add_argument("--user", required=True, help="Admin username")
    ap.add_argument("--passw", required=True, help="Admin password")
    ap.add_argument("--package", required=True, help="ACAP package Name= from list.cgi")
    ap.add_argument("--eap", required=True, help="Path to .eap file")
    ap.add_argument("--config", help="Path to param config file (key=value per line)")
    ap.add_argument("--workers", type=int, default=16, help="Parallel workers in subnet mode")
    ap.add_argument("--no-stop", action="store_true", help="Don't stop before remove")
    ap.add_argument("--prefer-http", action="store_true", help="Prefer HTTP if both open")
    ap.add_argument("--force-http", action="store_true", help="Force HTTP only")
    ap.add_argument("--force-https", action="store_true", help="Force HTTPS only")
    ap.add_argument("--usergroup", help="User group to use for param.cgi updates")
    ap.add_argument("--show-progress", action="store_true", help="Show per-camera step and upload progress")
    args = ap.parse_args()

    if args.ip:
        targets = [args.ip]
    elif args.subnet:
        targets = subnet_targets(args.subnet)
    else:
        raise SystemExit("Provide either --ip or --subnet")

    prefer_https = not args.prefer_http

    param_updates = load_param_updates(args.config) if args.config else None

    pbar = tqdm(total=len(targets), desc="Updating cameras", unit="cam") if tqdm else None
    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {
            ex.submit(
                update_one_camera,
                ip,
                args.user,
                args.passw,
                args.package,
                args.eap,
                stop_first=not args.no_stop,
                prefer_https=prefer_https,
                force_http=args.force_http,
                force_https=args.force_https,
                param_updates=param_updates,
                usergroup=args.usergroup,
                show_progress=args.show_progress,
            ): ip
            for ip in targets
        }

        for fut in as_completed(futs):
            try:
                ip, ok, msg = fut.result()
            except Exception as e:
                # last-resort guard; should not happen now
                ip = futs[fut]
                ok = False
                msg = f"worker crashed: {e}"

            results.append((ip, ok, msg))
            if pbar:
                pbar.update(1)

    if pbar:
        pbar.close()

    print("\nResults:")
    for ip, ok, msg in sorted(results):
        print(f"{ip}: {'OK' if ok else 'FAIL'} - {msg}")

    print("\nNotes:")
    print(" - Control calls allow longer response times and retry.")
    print(" - Stop/remove timeouts are non-fatal; camera may still complete them.")
    print(" - If upload returns Error: 10, Axis says to check system log/server report.")


if __name__ == "__main__":
    main()
