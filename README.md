# Network Control Panel

An Arabic RTL control panel for a Kali Linux IPv4 gateway, with MAC access policies, subscriber accounts, traffic limits, service monitoring and links to local file storage and remote desktop.

**Status: developer preview.** This is a sanitized source distribution, not a general-purpose router installer. Its fixed LAN addressing and privileged networking integration must be reviewed before deployment. Fresh-machine installation has not been validated.

## Included

- Python/Flask administration and subscriber portal.
- nftables access control and Linux traffic control integration.
- Arabic Command Deck interface and original SVG MOH emblem.
- Local server monitoring and optional FileBrowser password-change integration.
- Example systemd service definitions and a non-activating source installer.

FileBrowser, XRDP, their binaries/configurations and user files are **not bundled**. They must be installed and configured separately. There is no browser-based desktop implementation in this package.

## Requirements and topology

Kali Linux, Python 3, Flask, Werkzeug, psutil, Gunicorn, nftables, iproute2, iptables and dnsmasq. Optional WireGuard support requires additional setup.

The current code assumes LAN `192.168.5.0/24`, gateway `192.168.5.1`, and management address `192.168.100.1`. These are documented example defaults, not automatically detected settings. Address assumptions also occur in firewall rules and templates; changing one constant is insufficient. Interface names can be supplied through `KNP_LAN` and `KNP_WAN`.

## Prepare the source

```sh
sudo apt install python3-flask python3-werkzeug python3-psutil gunicorn nftables iproute2 iptables dnsmasq openssl
sudo bash scripts/install-source.sh
```

The script copies source only. It does not create accounts, change routes, activate firewall rules or start services. Complete the reviewed deployment steps in [INSTALL.md](docs/INSTALL.md) before enabling any service.

## Security and scope

This application manages firewall state as root. Keep it on a trusted LAN. Administration requires HTTPS, a locally generated secret/password hash, and CSRF tokens. Never use the Flask development server for deployment.

MAC addresses can be spoofed; a MAC allowlist is not cryptographic identity. Subscriber sign-in currently uses HTTP. Use this only with explicit awareness of that limitation; do not reuse sensitive passwords. DNS logs can contain private browsing metadata.

No private keys, runtime databases, customer accounts, device lists, credentials or disk contents belong in this repository. See [SECURITY.md](SECURITY.md).

## Arabic

هذه نسخة مصدر مخصصة للنشر، منفصلة عن الخادم الفعلي. تتضمن اللوحة والواجهة وشعار MOH، دون حساباتك أو مفاتيحك أو ملفات المستخدمين. التثبيت الشامل على جهاز جديد يحتاج إعداد الشبكة والشهادات والخدمات ومراجعته؛ هذه النسخة ليست مثبتًا تلقائيًا مكتملًا.

## License

Copyright © 2026 Mohammed R Almasri. Original project code is distributed under the MIT License. Third-party dependencies retain their respective licenses; none of their binaries are redistributed here.

## Author / المؤلف

Mohammed R Almasri · [Instagram](https://www.instagram.com/masri206/) · [Facebook](https://www.facebook.com/Masri206) · [WhatsApp](https://wa.me/972599188222)

[Contact details](AUTHOR.md)

