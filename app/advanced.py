"""MOH v2: MAC policies, local Hotspot accounts and bounded service discovery."""
import concurrent.futures
import copy
import datetime
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import time
from urllib.parse import urlencode
from flask import abort, jsonify, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

MAC_RE = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z')


def valid_mac(value):
    value = str(value).strip().lower().replace('-', ':')
    if not MAC_RE.fullmatch(value) or int(value[:2], 16) & 1 or value == '00:00:00:00:00:00':
        raise ValueError('عنوان MAC غير صحيح')
    return value


def speed(value):
    n = float(value)
    if not (n == 0 or .1 <= n <= 1000):
        raise ValueError('السرعة صفر بلا حد، أو بين 0.1 و1000 Mbps')
    return n


def direct_active(rule, hotspot, ip=None):
    """A plain MAC exemption is convenience, never a cryptographic identity."""
    expiry = rule.get('direct_expires', 0)
    return (bool(rule.get('direct_access') or rule.get('full_speed'))
            and not hotspot.get('require_login_for_all') and not hotspot.get('key_only')
            and (expiry == 0 or expiry > time.time())
            and (not rule.get('bound_ip') or rule['bound_ip'] == ip))


def attach(p):
    raw_load, raw_devices, raw_tc = p.load_state, p.devices, p.tc_apply
    app, base = p.app, p.BASE
    last_tc = [None]
    last_error = ['']
    scan_gate = threading.BoundedSemaphore(2)
    scan_times = {}
    traffic_previous = {}

    def load():
        state = raw_load()
        state.setdefault('mac_rules', {})
        state.setdefault('users', {})
        state.setdefault('sessions', {})
        state.setdefault('admin_macs', [])
        state.setdefault('hotspot', {'enabled': False, 'default_down': 0, 'default_up': 0})
        state['hotspot'].setdefault('require_login_for_all', False)
        state['hotspot'].setdefault('key_only', False)
        state.setdefault('portal', {'network_name': 'MOH Network', 'headline': 'تسجيل الدخول إلى شبكة MOH',
            'description': 'أدخل اسم المستخدم وكلمة المرور للاتصال بالإنترنت.',
            'announcement': '', 'support_label': 'لطلب حساب إنترنت أو الاستفسار', 'support_phone': '',
            'footer': 'MOH Network', 'theme': 'ocean'})
        state.setdefault('trial', {'enabled': True, 'minutes':10, 'down': 5, 'up': 1})
        state['trial'].setdefault('minutes', 10)
        state['trial'].setdefault('shared', True)
        state.setdefault('trials', {})
        state.setdefault('security', {'isolate_upstream': True})
        return state

    p.load_state = load

    def peer_mac(ip):
        ip = p.validate_ip(ip)
        for attempt in range(4):
            rows = json.loads(p.run(['ip', '-j', 'neigh', 'show', 'to', ip, 'dev', p.LAN]).stdout)
            for row in rows:
                if row.get('dst') == ip and row.get('lladdr') and not any(x in row.get('state', []) for x in ('FAILED', 'INCOMPLETE')):
                    return valid_mac(row['lladdr'])
            if attempt == 0:
                # Trigger kernel ARP discovery without trusting an old DHCP lease.
                import socket
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                        probe.bind((p.GATEWAY, 0))
                        probe.sendto(b'', (ip, 9))
                except OSError:
                    pass
            if attempt < 3:
                time.sleep(.2)
        raise ValueError('تعذّر التحقق من MAC الجهاز. أعد فتح الصفحة بعد لحظات.')

    def active_sessions(state):
        now = time.time()
        result = {mac: s for mac, s in state['sessions'].items()
                if (s.get('expires') == 0 or s.get('expires', 0) > now)
                and state['users'].get(s.get('user'), {}).get('enabled')}
        for mac, trial in state.get('trials', {}).items():
            if mac not in result and trial.get('expires', 0) > now:
                result[mac] = dict(trial, user='@trial', trial=True)
        return result

    def resolve(state):
        known = raw_devices()
        sessions = active_sessions(state)
        result = {}
        for ip, device in known.items():
            mac = device.get('mac', '').lower()
            rule = state['mac_rules'].get(mac, {})
            login = sessions.get(mac)
            if login and login.get('ip') != ip:
                login = None
            protected = mac in state['admin_macs']
            legacy = state.get('devices', {}).get(ip, {})
            full = bool(rule.get('full_speed'))
            bypass = direct_active(rule, state['hotspot'], ip)
            if bypass and login and login.get('trial'):
                login = None
            user = (state.get('trial', {}) if login.get('trial') else state['users'].get(login['user'], {})) if login else {}
            blocked = bool(rule.get('blocked', legacy.get('blocked', False))) and not protected
            down = rule.get('down', user.get('down', state['hotspot'].get('default_down', 0)))
            up = rule.get('up', user.get('up', state['hotspot'].get('default_up', 0)))
            if not rule and legacy:
                down, up = legacy.get('down', down), legacy.get('up', up)
            if login and login.get('trial'):
                # Trial limits are a ceiling even when an old MAC policy is faster.
                full = False
                for field in ('down', 'up'):
                    limit = state['trial'].get(field, 0)
                    device_limit = rule.get(field, 0)
                    actual = min(limit, device_limit) if limit and device_limit else (limit or device_limit)
                    if field == 'down': down = actual
                    else: up = actual
            result[ip] = {'blocked': blocked, 'down': 0 if full else down, 'up': 0 if full else up,
                          'full_speed': full, 'protected': protected,
                          'allowed': not blocked and not state['hotspot'].get('key_only', False) and (bypass or bool(login) or not state['hotspot']['enabled']),
                          'direct_access': bypass, 'direct_expires': rule.get('direct_expires', 0),
                          'user': login['user'] if login else '',
                          'trial': bool(login and login.get('trial')),
                          'trial_shared': bool(login and login.get('trial') and state.get('trial',{}).get('shared', True)),
                          'expires': login['expires'] if login else 0, 'mac': mac}
        return known, result

    def effective_tc(state):
        _, policies = resolve(state)
        result = {'devices': {ip: value for ip, value in policies.items() if value.get('up') or value.get('down')}}
        if state.get('trial', {}).get('shared', True) and any(v.get('trial') and v['allowed'] for v in policies.values()):
            result['trial_pool'] = {'down':state['trial'].get('down',0), 'up':state['trial'].get('up',0)}
        return result

    def tc_apply(state):
        # Explicit empty state is the uninstall operation; do not load defaults here.
        if set(state) == {'devices'} and not state['devices']:
            raw_tc(state)
            last_tc[0] = None
            return
        value = effective_tc(state)
        fingerprint = json.dumps(value, sort_keys=True)
        if last_tc[0] != fingerprint:
            raw_tc(value)
            last_tc[0] = fingerprint

    p.tc_apply = tc_apply

    def access_script(state):
        _, policies = resolve(state)
        now = time.time()
        sessions = active_sessions(state)
        blocked_mac = {mac for mac, r in state['mac_rules'].items() if r.get('blocked') and mac not in state['admin_macs']}
        blocked_ips = {ip for ip, r in policies.items() if r['blocked']}
        allowed_mac = {}
        for ip, policy in policies.items():
            mac = policy['mac']
            rule = state['mac_rules'].get(mac, {})
            if direct_active(rule, state['hotspot'], ip) and mac not in blocked_mac:
                expiry = rule.get('direct_expires', 0)
                allowed_mac[mac] = 0 if expiry == 0 else max(1, int(expiry - now))
        for mac, login in sessions.items():
            if mac not in blocked_mac and mac not in allowed_mac:
                allowed_mac[mac] = 0 if login['expires'] == 0 else max(1, int(login['expires'] - now))
        allowed_ip, allowed_pair = {}, {}
        for ip, rule in policies.items():
            if rule['mac'] in allowed_mac and rule['allowed']:
                allowed_ip[ip] = allowed_mac[rule['mac']]
                allowed_pair[rule['mac'] + ' . ' + ip] = allowed_mac[rule['mac']]
        lines = []
        for name, values in [('blocked', blocked_ips), ('blocked_macs', blocked_mac)]:
            lines.append(f'flush set inet {p.TABLE} {name}')
            if values:
                lines.append(f'add element inet {p.TABLE} {name} {{ ' + ', '.join(sorted(values)) + ' }')
        for name, values in [('allowed_macs', allowed_mac), ('allowed_ips', allowed_ip), ('allowed_pairs', allowed_pair)]:
            lines.append(f'flush set inet {p.TABLE} {name}')
            if values:
                elements = [v + (f' timeout {ttl}s' if ttl else '') for v, ttl in values.items()]
                lines.append(f'add element inet {p.TABLE} {name} {{ ' + ', '.join(elements) + ' }')
        lines += [f'flush chain inet {p.TABLE} access', f'flush chain inet {p.TABLE} portal_nat',
                  f'add rule inet {p.TABLE} access iifname "{p.WAN}" ip saddr 192.168.5.0/24 drop',
                  f'add rule inet {p.TABLE} access iifname "{p.WAN}" oifname "{p.LAN}" ct state != {{ established, related }} drop',
                  f'add rule inet {p.TABLE} access iifname "{p.LAN}" ether saddr @blocked_macs drop',
                  f'add rule inet {p.TABLE} access iifname "{p.LAN}" ip saddr @blocked drop',
                  f'add rule inet {p.TABLE} access oifname "{p.LAN}" ip daddr @blocked drop']
        if state.get('security', {}).get('isolate_upstream', True):
            # Routed access only. L2 packets switched by an AP never enter this gateway.
            lines += [f'add rule inet {p.TABLE} access iifname "{p.LAN}" ip saddr != 192.168.5.0/24 drop',
                      f'add rule inet {p.TABLE} access iifname "{p.LAN}" oifname "{p.LAN}" drop',
                      f'add rule inet {p.TABLE} access iifname "{p.LAN}" oifname "{p.WAN}" ip daddr {{ 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 }} drop',
                      f'add rule inet {p.TABLE} access iifname "{p.LAN}" meta nfproto ipv6 drop',
                      f'add rule inet {p.TABLE} access oifname "{p.LAN}" meta nfproto ipv6 drop']
        if state['hotspot'].get('key_only'):
            lines += [f'add rule inet {p.TABLE} access iifname "{p.LAN}" drop',
                      f'add rule inet {p.TABLE} access oifname "{p.LAN}" drop',
                      f'add rule inet {p.TABLE} portal_nat iifname "{p.LAN}" tcp dport 80 redirect to :80']
        elif state['hotspot']['enabled']:
            # No routed IPv6 bypass while Hotspot controls the verified IPv4 LAN.
            lines += [f'add rule inet {p.TABLE} access iifname "{p.LAN}" meta nfproto ipv6 drop',
                      f'add rule inet {p.TABLE} access oifname "{p.LAN}" meta nfproto ipv6 drop',
                      f'add rule inet {p.TABLE} access iifname "{p.LAN}" ether saddr . ip saddr != @allowed_pairs drop',
                      f'add rule inet {p.TABLE} access oifname "{p.LAN}" ip daddr != @allowed_ips drop',
                      f'add rule inet {p.TABLE} portal_nat iifname "{p.LAN}" ether saddr . ip saddr != @allowed_pairs tcp dport 80 redirect to :80']
        return '\n'.join(lines) + '\n'

    def apply_blocks(state):
        p.run(['nft', '-f', '-'], access_script(state))

    p.apply_blocks = apply_blocks

    def nft_init(check_only=False):
        state = load()
        if state.get('version', 1) < 2:
            known = raw_devices()
            for ip, legacy in list(state['devices'].items()):
                mac = known.get(ip, {}).get('mac', '').lower()
                if MAC_RE.fullmatch(mac):
                    state['mac_rules'].setdefault(mac, dict(legacy, full_speed=False,
                                                          name=known[ip].get('name', ''), last_ip=ip))
                    del state['devices'][ip]
            state['version'] = 2
            if not check_only:
                p.atomic_json(base / 'state.json', state)
        exists = p.run(['nft', 'list', 'table', 'inet', p.TABLE], check=False).returncode == 0
        lines = [f'delete table inet {p.TABLE}'] if exists else []
        lines += [f'add table inet {p.TABLE}',
                  f'add set inet {p.TABLE} blocked {{ type ipv4_addr; }}',
                  f'add set inet {p.TABLE} blocked_macs {{ type ether_addr; }}',
                  f'add set inet {p.TABLE} allowed_macs {{ type ether_addr; flags timeout; }}',
                  f'add set inet {p.TABLE} allowed_ips {{ type ipv4_addr; flags timeout; }}',
                  f'add set inet {p.TABLE} allowed_pairs {{ type ether_addr . ipv4_addr; flags timeout; }}',
                  f'add chain inet {p.TABLE} access',
                  f'add chain inet {p.TABLE} input_guard {{ type filter hook input priority -10; policy accept; }}',
                  f'add rule inet {p.TABLE} input_guard iifname "{p.WAN}" ip saddr 192.168.5.0/24 drop',
                  f'add rule inet {p.TABLE} input_guard iifname "{p.WAN}" ct state established,related accept',
                  f'add rule inet {p.TABLE} input_guard iifname "{p.WAN}" udp sport 67 udp dport 68 accept',
                  f'add rule inet {p.TABLE} input_guard iifname "{p.WAN}" udp sport 547 udp dport 546 accept',
                  f'add rule inet {p.TABLE} input_guard iifname "{p.WAN}" meta l4proto ipv6-icmp accept',
                  f'add rule inet {p.TABLE} input_guard iifname "{p.WAN}" drop',
                  f'add chain inet {p.TABLE} portal_nat {{ type nat hook prerouting priority -110; policy accept; }}',
                  f'add chain inet {p.TABLE} forward {{ type filter hook forward priority -10; policy accept; }}',
                  f'add rule inet {p.TABLE} forward jump access']
        for n in range(2, 255):
            for prefix, interface, field in [('u', 'iifname', 'saddr'), ('d', 'oifname', 'daddr')]:
                lines += [f'add counter inet {p.TABLE} {prefix}{n}',
                          f'add rule inet {p.TABLE} forward {interface} "{p.LAN}" ip {field} 192.168.5.{n} counter name {prefix}{n}']
        script = '\n'.join(lines) + '\n' + access_script(state)
        p.run(['nft', '-c', '-f', '-'], script)
        if not check_only:
            p.run(['nft', '-f', '-'], script)

    p.nft_init = nft_init

    def devices():
        state = load()
        known, policies = resolve(state)
        for ip, value in known.items():
            rule = state['mac_rules'].get(value.get('mac', '').lower(), {})
            value['name'] = rule.get('name') or value.get('name', '')
            value['policy'] = policies[ip]
        return known

    p.devices = devices

    def collect_history(known=None, counts=None):
        """ARP reachability or new forwarded bytes are evidence, not DHCP alone."""
        path = base / 'history.json'
        history = json.loads(path.read_text()) if path.exists() else {}
        original = copy.deepcopy(history)
        now = int(time.time())
        if known is None:
            known = raw_devices()
        if counts is None:
            try:
                counts = p.counters()
            except (RuntimeError, ValueError, OSError):
                counts = {}
        best, totals = {}, {}
        for ip, item in known.items():
            try: mac = valid_mac(item.get('mac', ''))
            except ValueError: continue
            n = ip.split('.')[-1]
            totals[mac] = totals.get(mac, 0) + counts.get('u'+n, 0) + counts.get('d'+n, 0)
            old = best.get(mac)
            rank = lambda d: (bool(d.get('recent')), bool(d.get('name')), d.get('ip') == history.get(mac, {}).get('last_ip'))
            if old is None or rank(item) > rank(old): best[mac] = item
        for mac, item in best.items():
            entry = history.setdefault(mac, {'first_recorded': now, 'last_seen': 0})
            entry.update(last_ip=item['ip'])
            if item.get('name'): entry['name'] = item['name']
            previous = traffic_previous.get(mac)
            evidence = item.get('recent') or (previous is not None and totals[mac] > previous)
            if evidence and now-entry.get('last_seen', 0) >= 15:
                entry['last_seen'] = now
            traffic_previous[mac] = totals[mac]
        # Retain older DHCP records too, without inventing a last-online time.
        leases = p.Path('/var/lib/misc/dnsmasq.leases')
        if leases.exists():
            for line in leases.read_text().splitlines():
                parts = line.split()
                if len(parts)<4: continue
                try: mac, ip = valid_mac(parts[1]), p.validate_ip(parts[2])
                except ValueError: continue
                if mac not in history:
                    history[mac] = {'first_recorded':now, 'last_seen':0, 'last_ip':ip,
                                    'name':parts[3] if parts[3]!='*' else ''}
        if history != original:
            p.atomic_json(path, history)
        return history

    p.collect_history = collect_history

    def commit(state, action, detail):
        old = load()
        try:
            tc_apply(state)
            apply_blocks(state)
            p.atomic_json(base / 'state.json', state)
        except Exception:
            last_tc[0] = None
            try:
                tc_apply(old)
                apply_blocks(old)
            except Exception:
                app.logger.exception('MOH rollback failed')
            raise
        with (base / 'audit.log').open('a') as f:
            f.write(json.dumps({'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                'admin': request.remote_addr, 'action': action, 'detail': detail}) + '\n')

    def api_errors(fn):
        from functools import wraps
        @wraps(fn)
        def wrapped(*args, **kwargs):
            try:
                with p.LOCK:
                    return fn(*args, **kwargs)
            except (ValueError, TypeError, RuntimeError, OSError) as exc:
                return jsonify(error=str(exc)), 400
        return wrapped

    def data():
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            raise ValueError('طلب غير صحيح')
        return value

    def boolean(value):
        if type(value) is not bool:
            raise ValueError('قيمة منطقية غير صحيحة')
        return value

    # An authenticated administrator's current physical device remains reachable.
    original_status = app.view_functions['status']
    def status():
        with p.LOCK:
            try:
                mac = peer_mac(request.remote_addr)
                state = load()
                if mac not in state['admin_macs']:
                    state['admin_macs'].append(mac)
                    commit(state, 'protect-admin', mac)
            except (ValueError, RuntimeError):
                pass
            response = original_status()
            if not hasattr(response, 'get_json'):
                return response
            result = response.get_json()
            if isinstance(result, dict):
                state = load()
                # Reuse the same snapshot; avoid extra nft/neighbor subprocesses
                # while holding the global state lock for every dashboard poll.
                snapshot = {d['ip']:d for d in result.get('clients',[])}
                counts = {}
                for ip, device in snapshot.items():
                    n = ip.split('.')[-1]
                    counts['u'+n] = device.get('up_bytes',0)
                    counts['d'+n] = device.get('down_bytes',0)
                history = collect_history(snapshot, counts)
                now = time.time()
                clients = {}
                for device in result.get('clients', []):
                    mac = device.get('mac', '').lower()
                    if not MAC_RE.fullmatch(mac): continue
                    old = clients.get(mac)
                    rank = lambda d: (bool(d.get('recent')), bool(d.get('name')), d.get('ip') == history.get(mac, {}).get('last_ip'))
                    if old is None or rank(device)>rank(old): clients[mac] = device
                for mac, record in history.items():
                    if mac not in clients:
                        rule = state['mac_rules'].get(mac, {})
                        clients[mac] = {'ip':record.get('last_ip',''), 'mac':mac,
                            'name':rule.get('name') or record.get('name',''), 'recent':False,
                            'neighbor':'HISTORY','up_bytes':0,'down_bytes':0,'up_bps':0,'down_bps':0,
                            'policy':dict(rule, protected=mac in state['admin_macs'], allowed=False)}
                    clients[mac]['last_seen'] = record.get('last_seen', 0)
                    clients[mac]['online'] = record.get('last_seen',0)>now-60
                result['clients'] = list(clients.values())
                online = sum(bool(d.get('online')) for d in result['clients'])
                result.update(brand='MOH', hotspot=state['hotspot'], security=state['security'], trial_count=sum(bool(s.get('trial')) for s in active_sessions(state).values()), advanced_error=last_error[0],
                              session_count=len(active_sessions(state)), user_count=len(state['users']),
                              online_count=online, offline_count=len(clients)-online, known_count=len(clients))
                return jsonify(result)
            return response
    app.view_functions['status'] = status

    @app.get('/api/config')
    def config():
        with p.LOCK:
            state = load()
            users = {name: {k: v for k, v in user.items() if k != 'password_hash'} for name, user in state['users'].items()}
            return jsonify(hotspot=state['hotspot'], users=users, rules=state['mac_rules'],
                           portal=state['portal'], trial=state['trial'], security=state['security'],
                           protected=state['admin_macs'], sessions=active_sessions(state), error=last_error[0])

    @app.context_processor
    def portal_context():
        with p.LOCK:
            state = load()
            brand = state['portal']
            phone = re.sub(r'[^+0-9]', '', brand.get('support_phone', ''))
            international = phone[2:] if phone.startswith('00') else phone.lstrip('+')
            if international.startswith('0'):
                international = '972' + international[1:]
            whatsapp = ''
            app_url = ''
            if brand.get('whatsapp_enabled', True) and re.fullmatch(r'[1-9][0-9]{6,14}', international):
                whatsapp = 'https://wa.me/' + international + '?' + urlencode({'text':'مرحبًا، أريد الحصول على حساب إنترنت لشبكة ' + brand['network_name']})
                app_url = 'whatsapp://send?' + urlencode({'phone':international,'text':'مرحبًا، أريد الحصول على حساب إنترنت لشبكة ' + brand['network_name']})
            return {'portal_brand': brand, 'trial_settings': state['trial'], 'server_now': int(time.time()),
                    'support_tel': phone, 'whatsapp_url': whatsapp, 'whatsapp_app_url':app_url,
                    'whatsapp_number':international if whatsapp else ''}

    @app.post('/api/portal/settings')
    @api_errors
    def portal_settings():
        value = data()
        fields = {'network_name':64, 'headline':100, 'description':240, 'announcement':240,
                  'support_label':80, 'support_phone':32, 'footer':100}
        brand = {}
        for field, limit in fields.items():
            text = value.get(field, '')
            if not isinstance(text, str) or len(text) > limit or any(ord(c) < 32 and c not in '\n\t' for c in text):
                raise ValueError('حقل غير صحيح أو طويل: ' + field)
            brand[field] = text.strip()
        if not brand['network_name'] or not brand['headline']:
            raise ValueError('اسم الشبكة والعنوان مطلوبان')
        if not re.fullmatch(r'[+0-9 ()-]*', brand['support_phone']):
            raise ValueError('رقم التواصل يقبل الأرقام و+ والأقواس والشرطات')
        if value.get('theme') not in ('ocean','mint','sky'):
            raise ValueError('اختر لوحة ألوان متاحة')
        brand['theme'] = value['theme']
        brand['whatsapp_enabled'] = boolean(value.get('whatsapp_enabled', True))
        state = load()
        state['portal'] = brand
        minutes=value.get('trial_minutes', 10)
        if type(minutes) is not int or not 1 <= minutes <= 1440:
            raise ValueError('مدة التجربة من دقيقة إلى 1440 دقيقة')
        state['trial'] = {'enabled':boolean(value.get('trial_enabled', False)),
                          'minutes':minutes,
                          'shared':boolean(value.get('trial_shared', state['trial'].get('shared', True))),
                          'down':speed(value.get('trial_down', 5)), 'up':speed(value.get('trial_up', 1))}
        commit(state, 'portal-settings', {'theme':brand['theme'], 'trial_enabled':state['trial']['enabled'],
               'trial_shared':state['trial']['shared'], 'trial_minutes':minutes,
               'trial_down':state['trial']['down'], 'trial_up':state['trial']['up']})
        return jsonify(ok=True)

    @app.post('/api/security')
    @api_errors
    def security_settings():
        state = load()
        state['security'] = {'isolate_upstream':boolean(data().get('isolate_upstream'))}
        commit(state, 'network-isolation', state['security'])
        return jsonify(ok=True)

    @app.get('/api/audit')
    def audit():
        with p.LOCK:
            path = base / 'audit.log'
            if not path.exists():
                return jsonify(events=[])
            with path.open('rb') as stream:
                stream.seek(0, 2)
                stream.seek(max(0, stream.tell()-80000))
                lines = stream.read().decode('utf-8', errors='replace').splitlines()
            result = []
            for line in reversed(lines):
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        result.append({k:event.get(k, '') for k in ('time','admin','action','detail')})
                except ValueError:
                    continue
                if len(result) >= 100:
                    break
            return jsonify(events=result)

    @app.post('/api/device')
    @api_errors
    def device_rule():
        value = data()
        mac = valid_mac(value.get('mac', ''))
        state = load()
        if value.get('delete'):
            if mac in state['admin_macs']:
                raise ValueError('جهاز الإدارة محمي')
            state['mac_rules'].pop(mac, None)
        else:
            previous = state['mac_rules'].get(mac, {})
            blocked = boolean(value.get('blocked', False))
            full = boolean(value.get('full_speed', False))
            direct = boolean(value.get('direct_access', full))
            down, up = speed(value.get('down', 0)), speed(value.get('up', 0))
            if (full or direct) and blocked:
                raise ValueError('ألغ الحظر قبل تفعيل الدخول المباشر')
            if mac in state['admin_macs'] and blocked:
                raise ValueError('جهاز الإدارة محمي من الحظر')
            rule = {'name': str(value.get('name', '')).strip()[:64], 'blocked': blocked, 'full_speed': full}
            rule['direct_access'] = direct or full
            minutes = value.get('direct_minutes')
            if minutes is not None and not 0 <= int(minutes) <= 43200:
                raise ValueError('مدة السماح من صفر إلى 43200 دقيقة')
            rule['direct_expires'] = previous.get('direct_expires', 0) if minutes is None else (int(time.time() + int(minutes) * 60) if int(minutes) else 0)
            bound = value.get('bound_ip', previous.get('bound_ip', ''))
            if bound:
                bound = p.validate_ip(bound)
                if 'bound_ip' in value and peer_mac(bound) != mac:
                    raise ValueError('عنوان IP لا يطابق MAC المرصود حاليًا')
                rule['bound_ip'] = bound
            if not boolean(value.get('inherit_speeds', False)):
                rule.update(down=down, up=up)
            state['mac_rules'][mac] = rule
        commit(state, 'device-rule', mac)
        return jsonify(ok=True)

    @app.post('/api/device/grant')
    @api_errors
    def grant_device():
        value = data()
        ip = p.validate_ip(value.get('ip', ''))
        mac = valid_mac(value.get('mac', ''))
        if peer_mac(ip) != mac:
            raise ValueError('تغيّر الجهاز أو عنوانه. حدّث القائمة ثم حاول مجددًا')
        minutes = int(value.get('minutes', 0))
        if not 0 <= minutes <= 43200:
            raise ValueError('المدة من صفر (مفتوحة) إلى 43200 دقيقة')
        state = load()
        if state['hotspot'].get('key_only') or state['hotspot'].get('require_login_for_all'):
            raise ValueError('الوضع الصارم يمنع الاستثناءات؛ استخدم حسابًا أو مفتاح WireGuard')
        state['mac_rules'][mac] = {'name': str(value.get('name', '')).strip()[:64],
            'blocked': False, 'full_speed': False, 'direct_access': True,
            'direct_expires': 0 if minutes == 0 else int(time.time() + minutes * 60),
            'down': speed(value.get('down', 0)), 'up': speed(value.get('up', 0))}
        commit(state, 'device-grant', {'mac': mac, 'ip': ip, 'minutes': minutes})
        return jsonify(ok=True)

    @app.post('/api/settings')
    @api_errors
    def settings():
        value = data()
        state = load()
        enabled = boolean(value.get('enabled'))
        if enabled and not any(u.get('enabled') for u in state['users'].values()):
            raise ValueError('أضف حساب Hotspot مفعّلًا قبل تشغيل بوابة الدخول')
        # Always preserve the administrator who enables the gate.
        if enabled and not ipaddress.ip_address(request.remote_addr).is_loopback:
            mac = peer_mac(request.remote_addr)
            if mac not in state['admin_macs']:
                state['admin_macs'].append(mac)
        key_only = boolean(value.get('key_only', state['hotspot'].get('key_only', False)))
        if key_only:
            from private_gateway import status as private_status
            if not private_status(p)['verified_peer']:
                raise ValueError('اختبر اتصال WireGuard أولًا؛ يلزم اتصال مشفر ناجح خلال آخر ثلاث دقائق')
        state['hotspot'] = {'enabled': enabled, 'key_only': key_only, 'default_down': speed(value.get('default_down', 0)),
                            'default_up': speed(value.get('default_up', 0)),
                            'require_login_for_all': boolean(value.get('require_login_for_all', state['hotspot'].get('require_login_for_all', False)))}
        commit(state, 'settings', state['hotspot'])
        return jsonify(ok=True)

    @app.post('/api/users')
    @api_errors
    def users():
        value = data()
        username = str(value.get('username', ''))
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,32}', username):
            raise ValueError('اسم المستخدم: أحرف إنجليزية أو أرقام أو . _ - حتى 32 محرفًا')
        state = load()
        previous_minutes = state['users'].get(username, {}).get('minutes')
        if value.get('delete'):
            state['users'].pop(username, None)
        else:
            password = value.get('password', '')
            if not isinstance(password, str) or len(password) > 128:
                raise ValueError('كلمة المرور غير صحيحة')
            if username not in state['users'] and len(password) < 1:
                raise ValueError('كلمة مرور المستخدم الجديد لا يمكن أن تكون فارغة')
            minutes, max_devices = int(value.get('minutes', 720)), int(value.get('max_devices', 1))
            if not (minutes == 0 or 5 <= minutes <= 10080) or not 1 <= max_devices <= 10:
                raise ValueError('المدة صفر لجلسة مفتوحة، أو بين 5 و10080 دقيقة؛ والأجهزة من 1 إلى 10')
            user = dict(state['users'].get(username, {}))
            user.update(down=speed(value.get('down', 0)), up=speed(value.get('up', 0)),
                        minutes=minutes, max_devices=max_devices, enabled=boolean(value.get('enabled', True)))
            if password:
                user['password_hash'] = generate_password_hash(password)
            state['users'][username] = user
        # Revocation applies immediately; a password change also ends previous sessions.
        state['sessions'] = {m: s for m, s in state['sessions'].items()
                             if s.get('user') != username or
                             (not value.get('delete') and state['users'][username].get('enabled') and not value.get('password'))}
        if not value.get('delete') and previous_minutes != state['users'][username]['minutes']:
            now = time.time()
            for login in state['sessions'].values():
                if login.get('user') == username and (login.get('expires') == 0 or login.get('expires', 0) > now):
                    duration = state['users'][username]['minutes']
                    login['expires'] = 0 if duration == 0 else int(now + duration * 60)
        commit(state, 'user-update', username)
        return jsonify(ok=True)

    @app.post('/api/sessions/revoke')
    @api_errors
    def revoke():
        mac = valid_mac(data().get('mac', ''))
        state = load()
        state['sessions'].pop(mac, None)
        if mac in state['trials']:
            state['trials'][mac]['expires'] = int(time.time())-1
        commit(state, 'session-revoke', mac)
        return jsonify(ok=True)

    @app.post('/api/admin/password')
    @api_errors
    def admin_password():
        value = data()
        current, new = value.get('current', ''), value.get('new', '')
        if not isinstance(current, str) or not isinstance(new, str) or not 12 <= len(new) <= 128:
            raise ValueError('كلمة المرور الجديدة من 12 إلى 128 محرفًا')
        attempts = p.FAILURES['password-change:' + request.remote_addr]
        now = time.time()
        while attempts and attempts[0] < now - 300:
            attempts.popleft()
        if len(attempts) >= 5:
            return jsonify(error='محاولات كثيرة؛ انتظر خمس دقائق'), 429
        if not check_password_hash(p.AUTH['password_hash'], current):
            attempts.append(now)
            raise ValueError('كلمة المرور الحالية غير صحيحة')
        attempts.clear()
        auth = dict(p.AUTH, password_hash=generate_password_hash(new), secret=secrets.token_hex(32))
        p.atomic_json(base / 'auth.json', auth)
        p.AUTH.update(auth)
        app.secret_key = auth['secret']
        session.clear()
        return jsonify(ok=True)

    # Keep old API clients from silently writing IP rules in the new MAC-based model.
    def old_policy():
        return jsonify(error='حدّث الصفحة لاستخدام سياسات MAC الجديدة'), 409
    app.view_functions['policy'] = old_policy

    def guest_info():
        state = load()
        mac = peer_mac(request.remote_addr)
        rule = state['mac_rules'].get(mac, {})
        protected = mac in state['admin_macs']
        login = active_sessions(state).get(mac)
        if login and login.get('ip') != request.remote_addr:
            login = None
        bypass = direct_active(rule, state['hotspot'], request.remote_addr)
        blocked = bool(rule.get('blocked')) and not protected
        allowed = not blocked and not state['hotspot'].get('key_only', False) and (not state['hotspot']['enabled'] or bypass or bool(login))
        return state, mac, login, bypass, blocked, allowed

    p.guest_info = guest_info
    p.resolve_clients = resolve

    def captive_probe_response():
        # Redirect the original phone probe path/Host to an absolute HTTP URL.
        # A relative redirect would send the phone back to its probe hostname.
        allowed = request.remote_addr == p.GATEWAY
        if not allowed:
            try:
                with p.LOCK:
                    allowed = guest_info()[-1]
            except (ValueError, RuntimeError, OSError):
                allowed = False
        if allowed:
            path = request.path.lower()
            if path in ('/generate_204','/gen_204'):
                return '', 204
            if path == '/connecttest.txt':
                return app.response_class('Microsoft Connect Test', mimetype='text/plain')
            if path == '/ncsi.txt':
                return app.response_class('Microsoft NCSI', mimetype='text/plain')
            if path in ('/hotspot-detect.html','/library/test/success.html') or 'captive.apple.com' == request.host.split(':')[0]:
                return app.response_class('<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>', mimetype='text/html')
        return redirect(p.PUBLIC_URL + '/', code=302)

    p.captive_probe_response = captive_probe_response

    @app.get('/portal/preview')
    def portal_preview():
        return render_template('guest.html', preview=True, gateway_view=False, mac='', login=None,
                               bypass=False, blocked=False, allowed=False, enabled=True, error='')

    @app.get('/portal')
    def portal():
        if request.remote_addr == p.GATEWAY:
            # A local browser/health check is not a downstream Hotspot client.
            # Render a preview without assigning a MAC or granting a session.
            return render_template('guest.html', gateway_view=True, mac='', login=None,
                                   bypass=False, blocked=False, allowed=False,
                                   enabled=load()['hotspot']['enabled'], error='')
        try:
            with p.LOCK:
                state, mac, login, bypass, blocked, allowed = guest_info()
                if allowed and request.path == '/':
                    return redirect('/status')
                return render_template('guest.html', mac=mac, login=login, bypass=bypass, key_only=state['hotspot'].get('key_only', False),
                                       blocked=blocked, allowed=allowed, enabled=state['hotspot']['enabled'], error='')
        except (ValueError, RuntimeError) as exc:
            return render_template('guest.html', error=str(exc), mac='', login=None, bypass=False,
                                   blocked=False, allowed=False, enabled=True), 503

    @app.post('/portal/login')
    def portal_login():
        with p.LOCK:
            try:
                state, mac, _, bypass, blocked, _ = guest_info()
                if state['hotspot'].get('key_only', False):
                    raise ValueError('هذه الشبكة تتطلب اتصال WireGuard بمفتاح جهازك')
                if blocked:
                    raise ValueError('هذا الجهاز محظور. راجع مدير الشبكة.')
                if bypass or not state['hotspot']['enabled']:
                    return redirect('/')
                now = time.time()
                attempts = p.FAILURES['guest:' + request.remote_addr]
                while attempts and attempts[0] < now - 300:
                    attempts.popleft()
                if len(attempts) >= 10:
                    raise ValueError('محاولات كثيرة. انتظر خمس دقائق.')
                username = request.form.get('username', '')
                user = state['users'].get(username, {})
                if not user.get('enabled') or not check_password_hash(user.get('password_hash', ''), request.form.get('password', '')):
                    attempts.append(now)
                    raise ValueError('اسم المستخدم أو كلمة المرور غير صحيحة')
                active = active_sessions(state)
                if sum(1 for m, s in active.items() if s['user'] == username and m != mac) >= user['max_devices']:
                    raise ValueError('الحساب وصل إلى عدد الأجهزة المسموح. سجّل الخروج من جهاز آخر.')
                attempts.clear()
                state['sessions'] = {m:s for m,s in active.items() if not s.get('trial')}
                state['sessions'][mac] = {'user': username, 'ip': p.validate_ip(request.remote_addr), 'started':int(now),
                                          'expires': 0 if user['minutes'] == 0 else int(now + user['minutes'] * 60)}
                commit(state, 'hotspot-login', {'user': username, 'mac': mac})
                if not session.get('admin'):
                    session['csrf'] = secrets.token_hex(24)
                return redirect('/status')
            except (ValueError, RuntimeError, OSError) as exc:
                return render_template('guest.html', error=str(exc), mac='', login=None,
                                       bypass=False, blocked=False, allowed=False, enabled=True), 400

    @app.post('/portal/logout')
    def portal_logout():
        with p.LOCK:
            try:
                state = load()
                mac = peer_mac(request.remote_addr)
                state['sessions'].pop(mac, None)
                if mac in state['trials']:
                    state['trials'][mac]['expires'] = int(time.time())-1
                commit(state, 'hotspot-logout', mac)
                return redirect('/signed-out')
            except (ValueError, RuntimeError, OSError):
                abort(503)

    @app.post('/portal/trial')
    def portal_trial():
        with p.LOCK:
            try:
                state, mac, login, bypass, blocked, _ = guest_info()
                if blocked or state['hotspot'].get('key_only'):
                    raise ValueError('التجربة غير متاحة لهذا الجهاز')
                if login or bypass or not state['hotspot']['enabled']:
                    return redirect('/contact' if request.form.get('return_to')=='contact' else '/status')
                if not state['trial']['enabled']:
                    raise ValueError('التجربة المجانية غير متاحة حاليًا')
                now = int(time.time())
                if state['trials'].get(mac, {}).get('next_allowed', 0) > now:
                    raise ValueError('استخدمت التجربة المجانية. تتاح مرة كل 24 ساعة لهذا الجهاز.')
                # Bound new sessions per source and globally, without storing browser secrets.
                for name, limit in [('trial:'+request.remote_addr, 3), ('trial:global', 100)]:
                    attempts = p.FAILURES[name]
                    while attempts and attempts[0] < now-300:
                        attempts.popleft()
                    if len(attempts) >= limit:
                        raise ValueError('طلبات كثيرة للتجربة. حاول بعد خمس دقائق.')
                state['trials'] = {m:t for m,t in state['trials'].items() if t.get('next_allowed', 0)>now-86400*7}
                if len(state['trials']) >= 4096:
                    raise ValueError('التجربة غير متاحة الآن. تواصل مع المدير.')
                minutes=state['trial']['minutes']
                state['trials'][mac] = {'ip':p.validate_ip(request.remote_addr), 'started':now, 'minutes':minutes,
                                       'expires':now+minutes*60, 'next_allowed':now+86400}
                commit(state, 'trial-start', {'mac':mac, 'minutes':minutes})
                p.FAILURES['trial:'+request.remote_addr].append(now)
                p.FAILURES['trial:global'].append(now)
                return redirect('/contact' if request.form.get('return_to')=='contact' else '/status')
            except (ValueError, RuntimeError, OSError) as exc:
                return render_template('guest.html', error=str(exc), mac='', login=None,
                                       bypass=False, blocked=False, allowed=False, enabled=True), 400

    @app.get('/captive-api')
    def captive_api():
        try:
            with p.LOCK:
                _, _, login, _, _, allowed = guest_info()
                result = {'captive': not allowed, 'user-portal-url': p.PUBLIC_URL + '/'}
                if login and login['expires'] > 0:
                    result['seconds-remaining'] = max(0, int(login['expires'] - time.time()))
                response = jsonify(result)
                response.content_type = 'application/captive+json'
                return response
        except (ValueError, RuntimeError):
            return jsonify(captive=True, **{'user-portal-url': p.PUBLIC_URL + '/'})

    @app.post('/api/services')
    def services():
        try:
            value = data()
            ip = p.validate_ip(value.get('ip', ''))
            if ip not in raw_devices():
                raise ValueError('اختر جهازًا معروفًا في الشبكة')
            if time.monotonic() - scan_times.get(request.remote_addr, -100) < 2:
                return jsonify(error='انتظر ثانيتين بين عمليتي فحص'), 429
            if not scan_gate.acquire(blocking=False):
                return jsonify(error='يوجد فحص جارٍ؛ حاول بعد لحظات'), 429
            scan_times[request.remote_addr] = time.monotonic()
            try:
                ports = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 139: 'NetBIOS', 445: 'SMB',
                         631: 'IPP طباعة', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP بديل',
                         8443: 'HTTPS بديل', 9100: 'منفذ طابعة'}
                def probe(item):
                    port, name = item
                    try:
                        with socket.create_connection((ip, port), timeout=.7):
                            url = f'{"https" if port in (443, 8443) else "http"}://{ip}:{port}/' if port in (80, 443, 8080, 8443) else None
                            return {'port': port, 'name': name, 'url': url}
                    except OSError:
                        return None
                with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                    found = [x for x in pool.map(probe, ports.items()) if x]
                return jsonify(ip=ip, services=found)
            finally:
                scan_gate.release()
        except (ValueError, RuntimeError, OSError) as exc:
            return jsonify(error=str(exc)), 400

    def reconcile():
        while True:
            try:
                with p.LOCK:
                    state = load()
                    tc_apply(state)
                    apply_blocks(state)
                    collect_history()
                    last_error[0] = ''
            except Exception as exc:
                last_error[0] = str(exc)[:400]
                app.logger.exception('MOH policy reconciliation failed')
            time.sleep(5)

    if os.environ.get('KNP_SERVICE') == '1' and p.__name__ != '__main__' and p.ROLE != 'guest':
        threading.Thread(target=reconcile, daemon=True, name='moh-policy-sync').start()

