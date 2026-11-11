#!/bin/bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo.'; exit 1; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
destination=/usr/local/lib/kali-net-panel
[[ ! -e "$destination" ]] || { echo 'Destination already exists; refusing to overwrite.'; exit 1; }
python3 -c 'import flask, werkzeug, psutil, gunicorn'
install -d -m 755 "$destination"
cp -R "$root/app/." "$destination/"
chown -R root:root "$destination"
chmod -R go-w "$destination"
echo 'Source installed only. Read docs/INSTALL.md before configuring services.'
