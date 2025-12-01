#!/usr/bin/env python3
"""
ACAP config-only updater using AXIS VAPIX Application + Parameter APIs.

This tool stops a running app, applies a parameter config file, and restarts
it without uploading/removing the `.eap` package.
"""

import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
except Exception:
    tqdm = None

from acap_update_app import (
    detect_scheme,
    load_param_updates,
    subnet_targets,
    tcp_port_open,
    vapix_app_control,
    vapix_app_list,
    vapix_param_update,
)


# -------------------- Config update flow --------------------


def update_config_one_camera(
    ip,
    username,
    password,
    package,
    param_updates,
    stop_first=True,
    prefer_https=True,
    force_http=False,
    force_https=False,
    usergroup=None,
):
    if force_http:
        scheme = "http" if tcp_port_open(ip, 80) else None
    elif force_https:
        scheme = "https" if tcp_port_open(ip, 443) else None
    else:
        scheme = detect_scheme(ip, prefer_https=prefer_https)

    if not scheme:
        return ip, False, "no http/https on 80/443"

    try:
        vapix_app_list(ip, username, password, scheme)
    except Exception as e:
        return ip, False, f"applications/list.cgi unavailable ({e})"

    stop_msg = "skipped"
    stop_ok = True
    if stop_first:
        stop_ok, stop_msg = vapix_app_control(
            ip, username, password, scheme, "stop", package
        )
        if not stop_ok and "not running" not in stop_msg.lower():
            return ip, False, f"stop failed: {stop_msg}"

    ok, msg = vapix_param_update(
        ip, username, password, scheme, param_updates, usergroup=usergroup
    )
    if not ok:
        return ip, False, f"config update failed: {msg}"

    time.sleep(1)

    start_ok, start_msg = vapix_app_control(
        ip, username, password, scheme, "start", package
    )
    if not start_ok and "already running" not in start_msg.lower():
        return ip, False, f"start failed: {start_msg}"

    try:
        apps = vapix_app_list(ip, username, password, scheme)
        status = next(
            (a["status"] for a in apps if a.get("name") == package), "unknown"
        )
    except Exception:
        status = "unknown"

    details = [f"stop={'OK' if stop_ok else stop_msg}", "config=OK", f"start={start_msg if start_msg else 'OK'}"]
    return ip, True, f"{'; '.join(details)}; status={status}"


# -------------------- Main --------------------


def main():
    ap = argparse.ArgumentParser(
        description="Update ACAP configuration via VAPIX without uploading a new package"
    )
    ap.add_argument("--ip", help="Single camera IP. If omitted, subnet mode is used.")
    ap.add_argument("--subnet", help="CIDR subnet to update, e.g. 192.168.1.0/24")
    ap.add_argument("--user", required=True, help="Admin username")
    ap.add_argument("--passw", required=True, help="Admin password")
    ap.add_argument("--package", required=True, help="ACAP package Name= from list.cgi")
    ap.add_argument(
        "--config", required=True, help="Path to param config file (key=value per line)"
    )
    ap.add_argument("--workers", type=int, default=16, help="Parallel workers in subnet mode")
    ap.add_argument("--no-stop", action="store_true", help="Do not stop the app before updating")
    ap.add_argument("--prefer-http", action="store_true", help="Prefer HTTP if both open")
    ap.add_argument("--force-http", action="store_true", help="Force HTTP only")
    ap.add_argument("--force-https", action="store_true", help="Force HTTPS only")
    ap.add_argument("--usergroup", help="User group to use for param.cgi updates")
    args = ap.parse_args()

    if args.ip:
        targets = [args.ip]
    elif args.subnet:
        targets = subnet_targets(args.subnet)
    else:
        raise SystemExit("Provide either --ip or --subnet")

    prefer_https = not args.prefer_http
    param_updates = load_param_updates(args.config)

    pbar = tqdm(total=len(targets), desc="Updating configs", unit="cam") if tqdm else None
    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {
            ex.submit(
                update_config_one_camera,
                ip,
                args.user,
                args.passw,
                args.package,
                param_updates,
                stop_first=not args.no_stop,
                prefer_https=prefer_https,
                force_http=args.force_http,
                force_https=args.force_https,
                usergroup=args.usergroup,
            ): ip
            for ip in targets
        }

        for fut in as_completed(futs):
            try:
                ip, ok, msg = fut.result()
            except Exception as e:
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
    print(" - Stops then restarts the target app around the config update.")
    print(" - Stop/start timeouts are treated as failures unless camera reports already stopped/running.")
    print(" - Provide a param config file with key=value lines; blank lines and # comments are ignored.")


if __name__ == "__main__":
    main()
