# Deployment checklist for administrators

1. Use a dedicated Kali test machine and console access. Record its existing routes, firewall rules and interface names. This preview does not configure arbitrary network topologies.
2. Prepare the documented LAN and management addresses. Configure dnsmasq to serve the LAN, with the gateway as router and DNS server. Configure the actual uplink separately.
3. Install dependencies and run `scripts/install-source.sh`. It refuses to overwrite an existing application directory.
4. Create `/var/lib/kali-net-panel` with root ownership and mode 0700. Generate a new `auth.json` containing a random `secret` and a Werkzeug `generate_password_hash` result in `password_hash`. Never copy production authentication data into this repository.
5. Generate a new local TLS certificate/key at `cert.pem` and `key.pem` in that state directory. Include the management IP in its SAN. Keep the private key mode 0600. Configure client trust explicitly.
6. Review both example systemd units, their interface environment, bind addresses, capabilities and dependencies. Their `share-internet.service` dependency requires a separately reviewed gateway service. No such service is installed by this package.
7. Review `network_boot.py` before using it: it can enable forwarding and add NAT/forwarding rules. Set `KNP_LAN` and `KNP_WAN` explicitly for every service that imports the panel. The historical Python fallback uplink is `wlan1`; do not assume it matches your device.
8. Check the firewall initialization in an isolated network namespace before starting the example units. Provision administrator protection for your own MAC; this release intentionally contains no trusted personal MAC addresses.
9. Install FileBrowser and XRDP independently if needed. The optional file integration currently uses an example account `admin` and URL `https://192.168.100.1:8444`. Update both integration code and templates to match your installation. The file API certificate must be placed at `/var/lib/kali-net-panel/files-cert.pem`.
10. Verify allowed/blocked clients, DHCP renewal, internet limits, local transfers, authentication, and a full reboot before using the machine as a gateway.

## Uninstalling the source-only installation

The provided installer starts no services and makes no network changes. Its default destination is `/usr/local/lib/kali-net-panel`. If you subsequently enabled services or firewall rules, stop and remove only the resources owned by this application before removing its source. Do not flush an existing firewall ruleset. Retain backups of runtime data separately.

## Known limitations

- Fixed addressing appears throughout the code; full topology configuration remains future work.
- The optional desktop/file integrations need external service setup.
- The preview does not include automated backup retention, a native recycle bin, DNS naming, or disk migration.
- No clean-machine end-to-end install test has been performed for this publication package.
