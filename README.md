# AXIS VAPIX API Tools

A small set of Python utilities for discovering **Axis network cameras** on a local subnet and querying them via **VAPIX**.  
Built to be practical on modern **AXIS OS 12.x**, where multicast discovery and older app-config endpoints may be disabled.

![Screenshot](https://github.com/jsammarco/AXIS_VAPIX_API_TOOLS/blob/main/discover_axis_vapix%20screenshot.jpg?raw=true)

---

## Features

- **Subnet discovery (no SSDP required)**  
  Scans an IP range and identifies Axis devices by calling the VAPIX Basic Device Info API.

- **Device inventory output**  
  For each discovered device, prints:
  - Hostname
  - IP address
  - Device type
  - Model
  - Product name
  - Serial number
  - AXIS OS / firmware version

- **ACAP app visibility**
  - Lists installed ACAP applications
  - Shows whether each app is **Running / Stopped / Idle**
  - Pulls app settings using the VAPIX Parameter API and prints them per‑app

- **Progress bar** during subnet scan (optional, via `tqdm`)

---

## Repository contents

- `discover_axis_vapix.py`
  Main discovery tool (subnet scan + device info + apps + params).

- `acap_update_app.py`
  Batch ACAP updater that stops/removes an existing package, uploads a new `.eap`, and restarts the app across single IPs or whole subnets.

- `acap_update_config.py`
  Stops a running app, applies parameter changes from a config file, and restarts the app without uploading a new `.eap`.

- `overlay.py`
  Dynamic Overlay helper that can run fully from the CLI or through an interactive menu to call `dynamicoverlay.cgi` methods.

- `discover_axis_vapix screenshot.jpg`  
  Example output screenshot.

---

## Requirements

- Python **3.8+**
- Packages:
  - `requests`
  - `tqdm` (optional but recommended for progress bar)

Install deps:

```bash
pip install requests tqdm
```

---

## Usage

Run a scan on your local subnet:

```bash
python discover_axis_vapix.py --subnet 192.168.1.0/24 --user root --passw "yourPassword"
```

### Common flags

- `--subnet`  
  CIDR subnet to scan. Example: `192.168.1.0/24`

- `--user` / `--passw`  
  Admin credentials. **Recommended**, and required to list ACAP apps + settings.

- `--workers`  
  Number of parallel probe threads (default is high for quick LAN scans).

- `--timeout`
  HTTP request timeout per host.

- `--param-timeout`
  Timeout for the **full parameter dump** (used to find app settings).

### Update ACAP apps with `acap_update_app.py`

Update a single camera:

```bash
python acap_update_app.py --ip 192.168.1.50 --user root --passw "yourPassword" --package MyAcap --eap /path/to/MyAcap.eap
```

Update every camera in a subnet (in parallel):

```bash
python acap_update_app.py --subnet 192.168.1.0/24 --user root --passw "yourPassword" --package MyAcap --eap /path/to/MyAcap.eap --workers 32
```

Parameters:

- `--ip`
  Single camera IP. Use this or `--subnet`.

- `--subnet`
  CIDR range to update (e.g., `192.168.1.0/24`).

- `--user` / `--passw`
  Admin credentials used for VAPIX upload/control calls.

- `--package`
  Package `Name` value as reported by `applications/list.cgi`.

- `--eap`
  Path to the `.eap` file to upload.

- `--config`
  Optional path to a param config file (key=value per line) to apply after uploading.

- `--workers`
  Parallel workers when running in subnet mode (default: 16).

- `--no-stop`
  Skip the pre-upload `stop` call (still attempts remove/upload/start).

- `--usergroup`
  User group to include in `param.cgi` updates when supplying a config file.

- `--prefer-http`
  Prefer HTTP when both 80 and 443 are open (HTTPS remains default).

- `--force-http` / `--force-https`
  Force a specific scheme when probing cameras.

### Update ACAP app configuration only with `acap_update_config.py`

Update a single camera's app configuration without uploading a new package:

```bash
python acap_update_config.py --ip 192.168.1.50 --user root --passw "yourPassword" --package MyAcap --config ./config.txt
```

Update a whole subnet in parallel:

```bash
python acap_update_config.py --subnet 192.168.1.0/24 --user root --passw "yourPassword" --package MyAcap --config ./config.txt --workers 32
```

Parameters:

- `--ip`
  Single camera IP. Use this or `--subnet`.

- `--subnet`
  CIDR range to update (e.g., `192.168.1.0/24`).

- `--user` / `--passw`
  Admin credentials used for VAPIX control and parameter calls.

- `--package`
  Package `Name` value as reported by `applications/list.cgi`.

- `--config`
  **Required** path to the param config file (key=value per line).

- `--workers`
  Parallel workers when running in subnet mode (default: 16).

- `--no-stop`
  Skip stopping the app before applying the config (defaults to stopping first).

- `--usergroup`
  User group to include in `param.cgi` updates.

- `--prefer-http`
  Prefer HTTP when both 80 and 443 are open (HTTPS remains default).

- `--force-http` / `--force-https`
  Force a specific scheme when probing cameras.

### Dynamic overlays with `overlay.py`

Call the **Dynamic Overlay API** either directly from the CLI or with a guided menu if you omit the method/IP flags.

- **Auto-detects HTTP/HTTPS** (prefers HTTPS if port 443 is open).
- Uses **Basic or Digest auth** automatically (`curl --anyauth` equivalent).
- Method-aware prompts in the interactive menu:
  - `addText` / `setText`: guided prompts for camera number, position, colors, and text (newlines normalized to `%0A`).
  - `addImage`: requests camera number, image path, and position.
  - `setImage`: asks for overlay identity plus optional overlay path and/or position updates.
  - `listImages`: sends the request without asking for parameters.
  - `remove`: prompts only for overlay identity (with optional context echo).
  - Other methods accept a single round of key=value pairs when parameters are needed.
  - Shows the JSON payload **and the equivalent curl command** before sending the request.

Run fully from the CLI:

```bash
python overlay.py --ip 192.168.1.185 --user root --passw "SuperSecurePass" \
  --method addText --param camera=1 --param position=topLeft \
  --param text="Hello from GPT" --param fontSize=18 --param textColor=white
```

Example output (payload + curl helper + JSON response):

```
--- Request ---
{
  "method": "addText",
  "apiVersion": "1.0",
  "params": {
    "camera": 1,
    "position": "topLeft",
    "text": "Hello from GPT",
    "fontSize": 18,
    "textColor": "white"
  }
}

Equivalent curl command:
curl --anyauth -u "root:SuperSecurePass" -H "Content-Type: application/json" --data "{\"method\":\"addText\",\"apiVersion\":\"1.0\",\"params\":{\"camera\":1,\"position\":\"topLeft\",\"text\":\"Hello from GPT\",\"fontSize\":18,\"textColor\":\"white\"}}" https://192.168.1.185/axis-cgi/dynamicoverlay/dynamicoverlay.cgi -k

--- Response ---
{
  "data": {
    "identity": 2
  },
  "apiVersion": "1.0",
  "context": null
}
```

Use the interactive menu when exploring capabilities or when you want prompts for parameters:

```bash
python overlay.py
```

You will be asked for the camera IP, credentials, and a method selection (covering overlay and upload methods). Each choice then prompts for the relevant params before issuing the request and printing the JSON response. For image overlays, `addImage` requests the camera number, overlay image path, and desired position, while `setImage` prompts for the overlay identity and any updates to `overlayPath` or `position`. `listImages` runs without asking for any parameters.

### `setImage`

Use `setImage` to update properties for an existing image overlay. Required and optional parameters mirror the Axis Dynamic Overlay API:

- `identity` (integer, required): which overlay to change.
- `overlayPath` (string, optional): path to the image file that should be displayed for the overlay.
- `position` (predefined keyword or `[x,y]` array, optional): accepts one of `top`, `topRight`, `bottomRight`, `bottom`, `bottomLeft`, `topLeft`, or a relative coordinate pair ranging from `-1.0` to `1.0` for both X and Y. If omitted, the position remains unchanged.
- `context` (string, optional): echoed back in the response when supplied.

Example request body:

```
{
  "apiVersion": "1.0",
  "context": "444",
  "method": "setImage",
  "params": {
    "identity": 3,
    "overlayPath": "/usr/local/images/logo.png",
    "position": "topRight"
  }
}
```

Successful responses include the echoed context (if present) and an empty `data` object:

```
{
  "apiVersion": "1.0",
  "method": "setImage",
  "context": "444",
  "data": {}
}
```

---

## Example output

Per‑device app/config listing first, then summary table:

```
== P1465-LE-LAB 192.168.1.185 (P1465-LE) ==
  - FireXXXXXXX v0.1.0 -> Running
      params:
        - ConfFireThresholdPercent = 75
        - ConfSmokeThresholdPercent = 65
        - LightstackIp = 192.168.1.233

HostName      | IP            | Type          | Model    | Name                        | Serial       | OS Version | Apps
-------------+---------------+---------------+----------+-----------------------------+--------------+------------+------------------------
P1465-LE-LAB  | 192.168.1.185 | Bullet Camera | P1465-LE | AXIS P1465-LE Bullet Camera | B8A44FE6XXXX | 12.6.97    | 4 installed (1 running)
```

---

## How it works

1. **Probe each IP** in the subnet for port **80/443**.
2. If open, call:

   **Basic Device Information API**  
   `POST /axis-cgi/basicdeviceinfo.cgi`  
   Used to identify Axis devices and fetch inventory fields.

3. For each Axis camera (with admin creds):

   **Application API**  
   `POST /axis-cgi/applications/list.cgi`  
   Returns installed ACAP apps + running state.

4. To find app settings on AXIS OS 12.x:

   **Parameter API (legacy CGI)**  
   `GET /axis-cgi/param.cgi?action=list`  
   The tool downloads the full parameter tree once per camera and filters keys
   that match app name/vendor tokens, then prints them under each app.

---

## Notes & limitations

- **SSDP/UPnP discovery is not used**  
  AXIS OS 12.x often disables multicast discovery by default, so subnet scan is the most reliable method.

- **App settings are heuristic‑matched**  
  Some 3rd‑party ACAPs do not expose configuration through VAPIX parameters; these will show “no matching keys found.”

- **Non‑standard ports**  
  If your cameras run HTTP/HTTPS on ports other than 80/443, you’ll need to extend the probe logic.

- **Credentials**  
  Without admin credentials you’ll still get device inventory, but **apps/settings will be skipped**.

---

## Contributing

Issues and PRs are welcome. If you add support for:
- alternate VAPIX endpoints
- non‑80/443 ports
- better per‑app settings discovery

please open a pull request.

---

## License

MIT License © 2025 Joseph Sammarco. See `LICENSE`.
