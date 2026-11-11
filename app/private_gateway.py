"""Optional authenticated IPv4 Internet overlay, independent of the public LAN.

Private client keys stay on clients. Only peer public keys are stored here.
This does not claim to isolate physical LAN broadcasts or hide client LAN IPs.
"""
import base64
import ipaddress
import json
import re
import shutil
import time
from flask import jsonify, request

IFACE, NETWORK, ADDRESS, PORT = 'mohwg0', '10.77.0.0/24', '10.77.0.1/24', 51820
TABLE = 'moh_private'


def load(p):
    path = p.BASE / 'private.json'
    return json.loads(path.read_text()) if path.exists() else {'peers': {}}


def public_key(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9+/]{43}=', value):
        raise ValueError('مفتاح WireGuard العام غير صحيح')
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32 or raw == bytes(32):
        raise ValueError('مفتاح WireGuard العام غير صحيح')
    return value


def peer_ip(value):
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or ip not in ipaddress.ip_network(NETWORK) or not 2 <= int(ip.packed[-1]) <= 254:
        raise ValueError('عنوان الشبكة الخاصة غير صحيح')
    return str(ip)


def firewall(p, state):
    """Never accept an overlay source on the physical LAN, including local input."""
    exists = p.run(['nft', 'list', 'table', 'inet', TABLE], check=False).returncode == 0
    lines = [f'delete table inet {TABLE}'] if exists else []
    lines += [f'add table inet {TABLE}',
        f'add set inet {TABLE} peers {{ type ipv4_addr; }}',
        f'add chain inet {TABLE} input {{ type filter hook input priority -30; policy accept; }}',
        f'add rule inet {TABLE} input iifname != "{IFACE}" ip saddr {NETWORK} drop',
        f'add rule inet {TABLE} input iifname != "{IFACE}" ip daddr {NETWORK} drop',
        f'add rule inet {TABLE} input iifname "{IFACE}" drop',
        f'add chain inet {TABLE} forward {{ type filter hook forward priority -30; policy accept; }}',
        f'add rule inet {TABLE} forward iifname != "{IFACE}" ip saddr {NETWORK} drop',
        f'add rule inet {TABLE} forward iifname "{IFACE}" meta nfproto ipv6 drop',
        f'add rule inet {TABLE} forward oifname "{IFACE}" meta nfproto ipv6 drop',
        f'add rule inet {TABLE} forward iifname "{IFACE}" ip saddr != @peers drop',
        f'add rule inet {TABLE} forward oifname "{IFACE}" ip daddr != @peers drop',
        f'add rule inet {TABLE} forward iifname "{IFACE}" ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }} drop',
        f'add rule inet {TABLE} forward iifname "{IFACE}" oifname != "{p.WAN}" drop',
        f'add rule inet {TABLE} forward oifname "{IFACE}" iifname != "{p.WAN}" drop',
        f'add rule inet {TABLE} forward oifname "{IFACE}" ct state != {{ established, related }} drop',
        f'add chain inet {TABLE} nat {{ type nat hook postrouting priority 99; policy accept; }}',
        f'add rule inet {TABLE} nat ip saddr {NETWORK} oifname "{p.WAN}" masquerade']
    ips = [peer_ip(peer['ip']) for peer in state['peers'].values() if peer['enabled']]
    if ips:
        lines += [f'add element inet {TABLE} peers {{ ' + ', '.join(ips) + ' }']
    return '\n'.join(lines) + '\n'


def wg_config(p, state):
    key = (p.BASE / 'wireguard.key').read_text().strip()
    public_key(key)  # Same encoding/length as a public key; never returned by the API.
    lines = ['[Interface]', 'PrivateKey = ' + key, 'ListenPort = ' + str(PORT)]
    for key, peer in state['peers'].items():
        if peer['enabled']:
            lines += ['[Peer]', 'PublicKey = ' + public_key(key), 'AllowedIPs = ' + peer_ip(peer['ip']) + '/32']
    return '\n'.join(lines) + '\n'


def shape(p, state):
    # Entire interface is MOH-owned; no qdiscs on eth0 or wlan1 are replaced.
    for part in ('root', 'ingress'):
        p.run(['tc', 'qdisc', 'del', 'dev', IFACE, part], check=False)
    peers = [v for v in state['peers'].values() if v['enabled']]
    if not any(v.get('down') or v.get('up') for v in peers):
        return
    p.run(['tc', 'qdisc', 'add', 'dev', IFACE, 'root', 'handle', '7:', 'htb', 'default', '999'])
    p.run(['tc', 'class', 'add', 'dev', IFACE, 'parent', '7:', 'classid', '7:999', 'htb', 'rate', '10000mbit'])
    if any(v.get('up') for v in peers):
        p.run(['tc', 'qdisc', 'add', 'dev', IFACE, 'handle', 'ffff:', 'ingress'])
    for peer in peers:
        ip = peer_ip(peer['ip'])
        minor = str(int(ip.split('.')[-1]) + 10)
        if peer.get('down'):
            p.run(['tc', 'class', 'add', 'dev', IFACE, 'parent', '7:', 'classid', '7:' + minor,
                   'htb', 'rate', str(float(peer['down'])) + 'mbit', 'ceil', str(float(peer['down'])) + 'mbit', 'quantum', '1514'])
            p.run(['tc', 'qdisc', 'add', 'dev', IFACE, 'parent', '7:' + minor, 'fq_codel'])
            p.run(['tc', 'filter', 'add', 'dev', IFACE, 'parent', '7:', 'protocol', 'ip', 'pref', minor,
                   'u32', 'match', 'ip', 'dst', ip + '/32', 'flowid', '7:' + minor])
        if peer.get('up'):
            p.run(['tc', 'filter', 'add', 'dev', IFACE, 'parent', 'ffff:', 'protocol', 'ip', 'pref', minor,
                   'u32', 'match', 'ip', 'src', ip + '/32', 'police', 'rate', str(float(peer['up'])) + 'mbit',
                   'burst', '128k', 'conform-exceed', 'drop/ok'])


def sync(p, state):
    # nft is an atomic batch; roll back whole operation in caller if wg/tc fails.
    p.run(['nft', '-f', '-'], firewall(p, state))
    config = p.BASE / '.wireguard-sync.conf'
    try:
        # Atomic writer creates a 0600 root-only file before replacement.
        import os
        fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(wg_config(p, state))
        p.run(['wg', 'syncconf', IFACE, str(config)])
    finally:
        config.unlink(missing_ok=True)
    shape(p, state)


def status(p):
    state = load(p)
    active = False
    latest, transfer = {}, {}
    if shutil.which('wg'):
        result = p.run(['wg', 'show', IFACE, 'latest-handshakes'], check=False)
        active = result.returncode == 0
        if active:
            latest = {line.split()[0]: int(line.split()[1]) for line in result.stdout.splitlines() if len(line.split()) == 2}
            result = p.run(['wg', 'show', IFACE, 'transfer'], check=False)
            transfer = {a[0]: {'received': int(a[1]), 'sent': int(a[2])}
                        for line in result.stdout.splitlines() if len(a := line.split()) == 3}
    peers = {key: dict(peer, handshake=latest.get(key, 0), **transfer.get(key, {})) for key, peer in state['peers'].items()}
    pubpath = p.BASE / 'wireguard.pub'
    return {'active': active, 'server_key': pubpath.read_text().strip() if pubpath.exists() else '',
            'endpoint': p.GATEWAY + ':' + str(PORT), 'network': NETWORK, 'peers': peers,
            'verified_peer': active and any(v['enabled'] and latest.get(k, 0) > time.time() - 180 for k, v in peers.items())}


def start(p):
    if not shutil.which('wg'):
        raise RuntimeError('Install wireguard-tools on Kali first')
    if not (p.BASE / 'wireguard.key').exists():
        raise RuntimeError('Use setup-private.sh to prepare the server key first')
    links = json.loads(p.run(['ip', '-j', 'link', 'show']).stdout)
    own = [v for v in links if v['ifname'] == IFACE]
    if own:
        # Never commandeer an interface created outside this module.
        if not (p.BASE / 'private-owned').exists():
            raise RuntimeError('mohwg0 already exists and is not MOH-owned')
    routes = json.loads(p.run(['ip', '-j', '-4', 'route', 'show', 'table', 'all']).stdout)
    for route in routes:
        dst = route.get('dst', 'default')
        if dst == 'default' or route.get('dev') == IFACE:
            continue
        if ipaddress.ip_network(dst, strict=False).overlaps(ipaddress.ip_network(NETWORK)):
            raise RuntimeError('10.77.0.0/24 overlaps an existing route; stopped without changing the LAN')
    # Install restrictive firewall before bringing up the authenticated interface.
    p.run(['nft', '-f', '-'], firewall(p, load(p)))
    if not own:
        p.run(['ip', 'link', 'add', IFACE, 'type', 'wireguard'])
        (p.BASE / 'private-owned').touch(mode=0o600)
    p.run(['ip', 'address', 'replace', ADDRESS, 'dev', IFACE])
    p.run(['ip', 'link', 'set', IFACE, 'mtu', '1380', 'up'])
    sync(p, load(p))
    # Accommodate existing iptables FORWARD policy; nft guards still apply first.
    for rule in (['-i', IFACE, '-o', p.WAN, '-s', NETWORK, '-j', 'ACCEPT'],
                 ['-i', p.WAN, '-o', IFACE, '-d', NETWORK, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT']):
        if p.run(['iptables', '-C', 'FORWARD'] + rule, check=False).returncode:
            p.run(['iptables', '-A', 'FORWARD'] + rule)
    p.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'])


def stop(p):
    if not (p.BASE / 'private-owned').exists():
        return
    p.run(['ip', 'link', 'delete', IFACE], check=False)
    for rule in (['-i', IFACE, '-o', p.WAN, '-s', NETWORK, '-j', 'ACCEPT'],
                 ['-i', p.WAN, '-o', IFACE, '-d', NETWORK, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT']):
        p.run(['iptables', '-D', 'FORWARD'] + rule, check=False)
    p.run(['nft', 'delete', 'table', 'inet', TABLE], check=False)
    (p.BASE / 'private-owned').unlink(missing_ok=True)


def attach(p):
    @p.app.get('/api/private')
    def private_status():
        with p.LOCK:
            return jsonify(status(p))

    @p.app.post('/api/private/peer')
    def private_peer():
        from advanced import speed
        try:
            with p.LOCK:
                value = request.get_json(silent=True)
                if not isinstance(value, dict):
                    raise ValueError('طلب غير صحيح')
                key = public_key(value.get('key', ''))
                old = load(p)
                if not status(p)['active']:
                    raise ValueError('شغّل setup-private.sh على كالي أولًا')
                state = json.loads(json.dumps(old))
                if value.get('delete') is True:
                    state['peers'].pop(key, None)
                else:
                    if type(value.get('enabled', True)) is not bool:
                        raise ValueError('حالة الجهاز غير صحيحة')
                    existing = state['peers'].get(key)
                    used = {v['ip'] for v in state['peers'].values()}
                    ip = existing['ip'] if existing else next((f'10.77.0.{n}' for n in range(2, 255) if f'10.77.0.{n}' not in used), None)
                    if not ip:
                        raise ValueError('وصلت الشبكة إلى عدد الأجهزة المتاح')
                    state['peers'][key] = {'name': str(value.get('name', '')).strip()[:64], 'ip': peer_ip(ip),
                        'enabled': value.get('enabled', True), 'down': speed(value.get('down', 0)), 'up': speed(value.get('up', 0))}
                try:
                    sync(p, state)
                    p.atomic_json(p.BASE / 'private.json', state)
                except Exception:
                    sync(p, old)
                    raise
                # Public keys identify devices but are not authentication secrets.
                with (p.BASE / 'audit.log').open('a') as stream:
                    stream.write(json.dumps({'time': time.time(), 'admin': request.remote_addr, 'action': 'private-peer', 'key': key}) + '\n')
                return jsonify(ok=True)
        except (ValueError, OSError, RuntimeError, TypeError) as exc:
            return jsonify(error=str(exc)), 400


if __name__ == '__main__':
    import sys
    import panel
    with panel.LOCK:
        stop(panel) if '--stop' in sys.argv else start(panel)
