#!/usr/bin/python3
"""LAN-only administration for the verified eth0/wlan1 NAT gateway."""
import collections
import copy
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time

import psutil
from process_lock import ProcessRLock, StateBusy
from flask import Flask, abort, jsonify, redirect, render_template, request, session
from werkzeug.security import check_password_hash

BASE = Path(os.environ.get('KNP_STATE', '/var/lib/kali-net-panel'))
LAN, WAN, GATEWAY = os.environ.get('KNP_LAN', 'eth0'), os.environ.get('KNP_WAN', 'wlan1'), '192.168.5.1'
if not all(re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', name) for name in (LAN, WAN)) or LAN == WAN:
    raise ValueError('Invalid LAN/WAN interface configuration')
ADMIN_HOST = '192.168.100.1'
NET = ipaddress.ip_network('192.168.5.0/24')
TABLE = 'kali_net_panel'
LOCK = ProcessRLock(BASE / '.state.lock')
ROLE = os.environ.get('KNP_ROLE', 'combined')
PUBLIC_URL = os.environ.get('KNP_PUBLIC_URL', 'http://192.168.5.1').rstrip('/')
ADMIN_URL = os.environ.get('KNP_ADMIN_URL', 'https://' + ADMIN_HOST).rstrip('/')
PREVIOUS = {}
FAILURES = collections.defaultdict(collections.deque)
STARTED = time.time()
app = Flask(__name__)
if (BASE / 'auth.json').exists():
    AUTH = json.loads((BASE / 'auth.json').read_text())
else:
    AUTH = {}
app.config.update(SECRET_KEY=AUTH.get('secret', secrets.token_hex(32)),
                  SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Strict', PERMANENT_SESSION_LIFETIME=3600,
                  MAX_CONTENT_LENGTH=8192)
if ROLE in ('admin', 'admin_lan', 'guest'):
    app.config.update(SESSION_COOKIE_SECURE=ROLE == 'admin_lan',
                      SESSION_COOKIE_NAME='MOH_GUEST' if ROLE == 'guest' else 'MOH_ADMIN')


def run(args, data=None, check=True):
    try:
        p = subprocess.run(args, input=data, text=True, capture_output=True, timeout=15)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('تأخر أمر النظام؛ تحقّق من حالة العملية قبل إعادة المحاولة') from exc
    if check and p.returncode:
        raise RuntimeError((p.stderr or p.stdout or 'Command failed').strip()[:600])
    return p


@app.errorhandler(StateBusy)
def state_busy(error):
    return jsonify(error='الإعدادات مشغولة بطلب آخر؛ انتظر قليلًا ثم حاول مجددًا'), 503, {'Retry-After':'3'}


REBOOT_PENDING = False


@app.post('/api/system/reboot')
def reboot_system():
    global REBOOT_PENDING
    # The standard before_request enforces administrator login, source and CSRF.
    if ROLE == 'guest' or not session.get('admin'):
        abort(403)
    value = request.get_json(silent=True) or {}
    if not isinstance(value, dict) or value.get('confirm') != 'REBOOT':
        return jsonify(error='يلزم تأكيد إعادة التشغيل'), 400
    password = value.get('password')
    if not isinstance(password, str) or not check_password_hash(AUTH.get('password_hash',''), password):
        return jsonify(error='كلمة مرور المدير غير صحيحة'), 403
    try:
        with LOCK:
            if REBOOT_PENDING:
                return jsonify(error='إعادة التشغيل مجدولة بالفعل'), 409
            # Fixed command only. PID 1 executes it after the HTTP reply is sent.
            run(['systemd-run','--unit=moh-panel-reboot','--on-active=10s',
                 '/usr/bin/systemctl','reboot'])
            REBOOT_PENDING = True
            with (BASE/'audit.log').open('a') as stream:
                stream.write(json.dumps({'time':time.time(),'admin':request.remote_addr,
                                         'action':'system-reboot','detail':'scheduled'})+'\n')
        return jsonify(ok=True,delay=10), 202
    except (RuntimeError,OSError) as exc:
        return jsonify(error=str(exc)), 503


def atomic_json(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2))
    tmp.chmod(0o600)
    tmp.replace(path)


def load_state():
    p = BASE / 'state.json'
    return json.loads(p.read_text()) if p.exists() else {'devices': {}}


def validate_ip(value):
    addr = ipaddress.ip_address(value)
    if addr not in NET or int(str(addr).split('.')[-1]) not in range(2, 255):
        raise ValueError('عنوان الجهاز خارج الشبكة المحلية')
    return str(addr)


def nft_init():
    exists = run(['nft', 'list', 'table', 'inet', TABLE], check=False).returncode == 0
    lines = [f'delete table inet {TABLE}'] if exists else []
    lines += [f'add table inet {TABLE}',
              f'add set inet {TABLE} blocked {{ type ipv4_addr; }}',
              f'add chain inet {TABLE} forward {{ type filter hook forward priority -10; policy accept; }}',
              f'add rule inet {TABLE} forward iifname "{LAN}" ip saddr @blocked drop',
              f'add rule inet {TABLE} forward oifname "{LAN}" ip daddr @blocked drop']
    for n in range(2, 255):
        for prefix, interface, field in [('u', 'iifname', 'saddr'), ('d', 'oifname', 'daddr')]:
            lines += [f'add counter inet {TABLE} {prefix}{n}',
                      f'add rule inet {TABLE} forward {interface} "{LAN}" ip {field} 192.168.5.{n} counter name {prefix}{n}']
    script = '\n'.join(lines) + '\n'
    run(['nft', '-c', '-f', '-'], script)
    run(['nft', '-f', '-'], script)


def apply_blocks(state):
    blocked = [validate_ip(ip) for ip, policy in state['devices'].items() if policy.get('blocked')]
    script = f'flush set inet {TABLE} blocked\n'
    if blocked:
        script += f'add element inet {TABLE} blocked {{ ' + ', '.join(blocked) + ' }\n'
    run(['nft', '-f', '-'], script)


def tc_apply(state):
    """Own only eth0 root 1: and ingress ffff:, after checking initial state."""
    pending_tc = []
    def flush_tc():
        if pending_tc:
            # All tokens are generated from fixed commands, validated IPs/rates.
            script='\n'.join(' '.join(args) for args in pending_tc)+'\n'
            run(['tc','-batch','-'],script)
            pending_tc.clear()
    def tc(args,check=True):
        if not check or '-j' in args:
            flush_tc()
            return run(args,check=check)
        pending_tc.append(args[1:])

    marker = BASE / 'tc-owned'
    policies = {ip: p for ip, p in state['devices'].items() if p.get('down') or p.get('up')}
    pool = state.get('trial_pool', {})
    if not policies and not marker.exists():
        return
    if not marker.exists():
        qdiscs = json.loads(tc(['tc', '-j', 'qdisc', 'show', 'dev', LAN]).stdout)
        if any(q.get('kind') in ('ingress', 'clsact') or
               (q.get('root') and q.get('kind') not in ('fq_codel', 'noqueue')) for q in qdiscs):
            raise RuntimeError('توجد إعدادات سرعة سابقة؛ يلزم فحصها قبل استبدالها')
        marker.write_text('fq_codel\n')
    tc(['tc', 'qdisc', 'del', 'dev', LAN, 'root'], check=False)
    tc(['tc', 'qdisc', 'del', 'dev', LAN, 'ingress'], check=False)
    if not policies:
        tc(['tc', 'qdisc', 'add', 'dev', LAN, 'root', 'fq_codel'])
        flush_tc()
        marker.unlink(missing_ok=True)
        return
    tc(['tc', 'qdisc', 'add', 'dev', LAN, 'root', 'handle', '1:', 'htb', 'default', '999'])
    tc(['tc', 'class', 'add', 'dev', LAN, 'parent', '1:', 'classid', '1:999',
         'htb', 'rate', '10000mbit', 'ceil', '10000mbit', 'quantum', '1514'])
    # Encrypted overlay transport has its own per-key limits on mohwg0.
    # Avoid applying the public client's IP limit a second time to that tunnel.
    tc(['tc', 'filter', 'add', 'dev', LAN, 'parent', '1:', 'protocol', 'ip', 'pref', '1',
         'flower', 'ip_proto', 'udp', 'src_ip', GATEWAY+'/32', 'src_port', '51820', 'flowid', '1:999'])
    # Local NAS/management replies must not inherit subscribers' internet caps.
    for pref, address in enumerate((ADMIN_HOST, GATEWAY), 2):
        tc(['tc','filter','add','dev',LAN,'parent','1:','protocol','ip','pref',str(pref),
            'flower','src_ip',address+'/32','flowid','1:999'])
    if pool.get('down'):
        cap = str(float(pool['down'])) + 'mbit'
        tc(['tc','class','add','dev',LAN,'parent','1:','classid','1:800',
             'htb','rate',cap,'ceil',cap,'quantum','1514'])
    if any(p.get('up') for p in policies.values()):
        tc(['tc', 'qdisc', 'add', 'dev', LAN, 'handle', 'ffff:', 'ingress'])
        tc(['tc', 'filter', 'add', 'dev', LAN, 'parent', 'ffff:', 'protocol', 'ip', 'pref', '1',
             'flower', 'ip_proto', 'udp', 'dst_ip', GATEWAY+'/32', 'dst_port', '51820', 'action', 'pass'])
        for pref, address in enumerate((ADMIN_HOST, GATEWAY), 2):
            tc(['tc','filter','add','dev',LAN,'parent','ffff:','protocol','ip','pref',str(pref),
                'flower','dst_ip',address+'/32','action','pass'])
    shared_upload_index = None
    trial_download_members = sum(bool(v.get('trial') and v.get('allowed') and v.get('down')) for v in policies.values())
    def police_indexes(value):
        if isinstance(value, dict):
            if value.get('kind') == 'police' and isinstance(value.get('index'), int):
                yield value['index']
            for child in value.values():
                yield from police_indexes(child)
        elif isinstance(value, list):
            for child in value:
                yield from police_indexes(child)
    for ip, policy in policies.items():
        validate_ip(ip)
        minor = str(int(ip.split('.')[-1]) + 10)
        in_pool = bool(pool and policy.get('trial') and policy.get('allowed'))
        if policy.get('down'):
            rate = str(float(policy['down'])) + 'mbit'
            guaranteed = float(policy['down'])
            if in_pool and pool.get('down'):
                # Child guarantees must not overbook the shared parent's rate.
                # Unused capacity is borrowed up to each child's ceil.
                guaranteed = min(guaranteed, float(pool['down']) / max(1, trial_download_members))
            tc(['tc', 'class', 'add', 'dev', LAN, 'parent', '1:800' if in_pool and pool.get('down') else '1:', 'classid', '1:' + minor,
                 'htb', 'rate', str(guaranteed)+'mbit', 'ceil', rate, 'quantum', '1514'])
            tc(['tc', 'qdisc', 'add', 'dev', LAN, 'parent', '1:' + minor, 'fq_codel'])
            tc(['tc', 'filter', 'add', 'dev', LAN, 'parent', '1:', 'protocol', 'ip',
                 'pref', minor, 'u32', 'match', 'ip', 'dst', ip + '/32', 'flowid', '1:' + minor])
        if policy.get('up'):
            command = ['tc', 'filter', 'add', 'dev', LAN, 'parent', 'ffff:', 'protocol', 'ip',
                       'pref', minor, 'u32', 'match', 'ip', 'src', ip + '/32']
            if in_pool and pool.get('up'):
                # All free-trial filters bind one kernel token bucket. An optional
                # lower device limit runs first, then pipes into the shared cap.
                if policy['up'] < pool['up']:
                    command += ['action','police','rate',str(float(policy['up']))+'mbit',
                                'burst','32k','conform-exceed','drop/pipe']
                if shared_upload_index is None:
                    command += ['action','police','rate',str(float(pool['up']))+'mbit',
                                'burst','32k','conform-exceed','drop/ok']
                else:
                    command += ['action','police','index',str(shared_upload_index)]
                tc(command)
                if shared_upload_index is None:
                    values=json.loads(tc(['tc','-j','filter','show','dev',LAN,'parent','ffff:','pref',minor]).stdout)
                    indexes=list(police_indexes(values))
                    if not indexes:
                        raise RuntimeError('تعذّر التحقق من مجموعة سرعة التجربة المشتركة')
                    shared_upload_index=indexes[-1]
            else:
                tc(command + ['police','rate',str(float(policy['up']))+'mbit','burst','128k',
                               'conform-exceed','drop/ok'])

    flush_tc()


def devices():
    result = {}
    leases = Path('/var/lib/misc/dnsmasq.leases')
    if leases.exists():
        for line in leases.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                try:
                    ip = validate_ip(parts[2])
                    if int(parts[0]) != 0 and int(parts[0]) < time.time():
                        continue
                    result[ip] = {'ip': ip, 'mac': parts[1], 'name': parts[3] if parts[3] != '*' else '',
                                  'neighbor': 'LEASE', 'recent': False}
                except ValueError:
                    continue
    neighbors = json.loads(run(['ip', '-j', 'neigh', 'show', 'dev', LAN]).stdout)
    for item in neighbors:
        try:
            ip = validate_ip(item['dst'])
        except ValueError:
            continue
        states = item.get('state', [])
        if 'lladdr' not in item or any(x in states for x in ('FAILED', 'INCOMPLETE')):
            continue
        result.setdefault(ip, {'ip': ip, 'name': '', 'mac': item['lladdr']})
        result[ip].update(mac=item['lladdr'], neighbor='/'.join(states), recent='REACHABLE' in states)
    for ip, policy in load_state()['devices'].items():
        result.setdefault(ip, {'ip': ip, 'name': '', 'mac': '', 'neighbor': 'SAVED', 'recent': False})
        result[ip]['policy'] = policy
    return result


def counters():
    data = json.loads(run(['nft', '-j', 'list', 'counters', 'table', 'inet', TABLE]).stdout)
    counts = {}
    for item in data.get('nftables', []):
        c = item.get('counter')
        if c and re.fullmatch('[ud][0-9]+', c.get('name', '')):
            counts[c['name']] = c.get('bytes', 0)
    return counts


def dns_recent():
    path = Path('/var/log/kali-net-panel/dns.log')
    if not path.exists():
        return []
    # Bounded tail; never read an arbitrarily large log into memory.
    with path.open('rb') as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 150000))
        lines = f.read().decode('utf-8', errors='replace').splitlines()
    rows = []
    for line in reversed(lines):
        m = re.search(r'query\[([^]]+)\]\s+(\S+)\s+from\s+(192\.168\.5\.\d+)', line)
        if m:
            rows.append({'time': line[:15], 'type': m[1], 'domain': m[2], 'ip': m[3]})
        if len(rows) >= 100:
            break
    return rows


@app.before_request
def protect():
    try:
        source = ipaddress.ip_address(request.remote_addr)
        if ROLE == 'admin' and not source.is_loopback:
            abort(403)
        if ROLE == 'admin_lan' and source not in NET and str(source) != ADMIN_HOST and not source.is_loopback:
            abort(403)
        if ROLE not in ('admin', 'admin_lan') and source not in NET:
            abort(403)
    except ValueError:
        abort(403)
    guest_paths = {'/', '/portal', '/portal/login', '/portal/logout', '/portal/trial', '/captive-api',
                   '/status','/session-info','/signout','/signed-out','/contact'}
    if ROLE == 'guest':
        if request.host.split(':')[0] == ADMIN_HOST:
            # The management HTTP socket redirects only; it never receives a login.
            if request.method in ('GET', 'HEAD') and request.path in ('/', '/login'):
                return redirect(ADMIN_URL + request.path, code=302)
            abort(404)
        if request.path == '/':
            if request.method not in ('GET', 'HEAD'):
                abort(405)
            if request.headers.get('Host','').split(':')[0] != GATEWAY:
                return captive_probe_response()
        if request.path == '/admin' and request.method in ('GET', 'HEAD'):
            return redirect(ADMIN_URL + '/')
        if request.path not in guest_paths and not request.path.startswith('/static/'):
            if request.method in ('GET', 'HEAD') and request.path not in ('/login','/logout','/portal/preview') and not request.path.startswith('/api/'):
                return captive_probe_response()
            abort(404)
    if ROLE in ('admin', 'admin_lan') and request.path in guest_paths and request.path != '/':
        if request.method == 'GET':
            return redirect(PUBLIC_URL + request.path)
        abort(404)
    if request.path.startswith('/static/'):
        return
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(24)
    if request.method == 'POST':
        token = request.headers.get('X-CSRF-Token', request.form.get('csrf', ''))
        if not secrets.compare_digest(token, session['csrf']):
            abort(403)
    public = {'/login', '/portal', '/portal/login', '/portal/logout', '/portal/trial', '/captive-api',
              '/status','/session-info','/signout','/signed-out','/contact'}
    if ROLE == 'guest':
        public.add('/')
    if request.path not in public and not session.get('admin'):
        if request.path.startswith('/api/'):
            return jsonify(error='يرجى تسجيل الدخول'), 401
        next_path = request.path if request.path in {'/home', '/apps/files', '/apps/desktop', '/apps/password', '/apps/system', '/server'} else ''
        return redirect('/login?next=' + next_path if next_path else '/login')


@app.after_request
def headers(response):
    response.headers.update({'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                             'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
                             'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
    return response


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        with LOCK:
            attempts = FAILURES[request.remote_addr]
            now = time.time()
            while attempts and attempts[0] < now - 300:
                attempts.popleft()
            if len(attempts) >= 10:
                return render_template('login.html', error='محاولات كثيرة؛ انتظر خمس دقائق'), 429
            if request.form.get('username') == 'admin' and check_password_hash(AUTH.get('password_hash', ''), request.form.get('password', '')):
                attempts.clear()
                session.clear()
                session.update(admin=True, csrf=secrets.token_hex(24))
                session.permanent = True
                next_path = request.args.get('next', '')
                return redirect(next_path if next_path in {'/home', '/apps/files', '/apps/desktop', '/apps/password', '/apps/system', '/server'} else '/')
            attempts.append(now)
        error = 'اسم المستخدم أو كلمة المرور غير صحيحة'
    return render_template('login.html', error=error)


@app.post('/logout')
def logout():
    session.clear()
    return redirect('/login')


@app.get('/')
def index():
    if ROLE == 'guest':
        return app.view_functions['portal']()
    return render_template('admin.html', admin_ip=request.remote_addr)


@app.get('/api/status')
def status():
    with LOCK:
        try:
            current = counters()
            clients = devices()
            now = time.monotonic()
            for ip, c in clients.items():
                n = ip.split('.')[-1]
                up, down = current.get('u' + n, 0), current.get('d' + n, 0)
                prev = PREVIOUS.get(ip)
                elapsed = now - prev[0] if prev else 0
                c.update(up_bytes=up, down_bytes=down, up_bps=0, down_bps=0)
                if prev and elapsed > 0:
                    c.update(up_bps=max(0, up - prev[1]) * 8 / elapsed,
                             down_bps=max(0, down - prev[2]) * 8 / elapsed)
                PREVIOUS[ip] = (now, up, down)
                c.setdefault('policy', {})
            vm = psutil.virtual_memory()
            return jsonify(clients=sorted(clients.values(), key=lambda x: ipaddress.ip_address(x['ip'])),
                           dns=dns_recent(), cpu=psutil.cpu_percent(), ram=vm.percent,
                           uptime=int(time.time() - psutil.boot_time()),
                           counter_since=int(STARTED), wan=WAN, lan=LAN,
                           gateway=GATEWAY, admin_ip=request.remote_addr,
                           download=sum(v for k, v in current.items() if k.startswith('d')),
                           upload=sum(v for k, v in current.items() if k.startswith('u')))
        except (RuntimeError, ValueError, OSError) as exc:
            app.logger.exception('Status failed')
            return jsonify(error=str(exc)), 503


@app.post('/api/policy')
def policy():
    try:
        data = request.get_json(silent=True) or {}
        ip = validate_ip(data.get('ip', ''))
        if ip == request.remote_addr:
            return jsonify(error='جهاز الإدارة محمي من الحظر وتحديد السرعة لتجنب فقدان التحكم'), 400
        if type(data.get('blocked')) is not bool:
            raise ValueError('قيمة الحظر غير صحيحة')
        value = {'blocked': data['blocked']}
        for key in ('up', 'down'):
            n = float(data.get(key, 0))
            if not (n == 0 or 0.1 <= n <= 1000):
                raise ValueError('السرعة: صفر بلا حد، أو من 0.1 إلى 1000 ميغابت/ثانية')
            value[key] = n
        with LOCK:
            old = load_state()
            new = copy.deepcopy(old)
            new['devices'][ip] = value
            try:
                if {k: v.get('up', 0) for k, v in old['devices'].items()} != {k: v.get('up', 0) for k, v in new['devices'].items()} or {k: v.get('down', 0) for k, v in old['devices'].items()} != {k: v.get('down', 0) for k, v in new['devices'].items()}:
                    tc_apply(new)
                apply_blocks(new)
                atomic_json(BASE / 'state.json', new)
            except Exception as original:
                try:
                    tc_apply(old)
                    apply_blocks(old)
                except Exception:
                    app.logger.exception('Policy rollback failed; administrator must inspect tc/nft')
                raise original
            with (BASE / 'audit.log').open('a') as f:
                f.write(json.dumps({'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                    'admin': request.remote_addr, 'ip': ip, 'policy': value}) + '\n')
        return jsonify(ok=True)
    except (ValueError, TypeError, RuntimeError, OSError) as exc:
        return jsonify(error=str(exc)), 400


from advanced import attach
attach(sys.modules[__name__])
from private_gateway import attach as attach_private
attach_private(sys.modules[__name__])
from subscriber import attach as attach_subscriber
attach_subscriber(sys.modules[__name__])

from server_center import attach as attach_server_center
attach_server_center(sys.modules[__name__])

if __name__ == '__main__':
    if sys.argv[1:] == ['--init']:
        BASE.mkdir(parents=True, exist_ok=True)
        nft_init()
        state = load_state()
        apply_blocks(state)
        tc_apply(state)
    elif sys.argv[1:] == ['--cleanup']:
        run(['nft', 'delete', 'table', 'inet', TABLE], check=False)
        tc_apply({'devices': {}})
    elif sys.argv[1:] == ['--check']:
        nft_init(check_only=True)
    else:
        raise SystemExit('Use the systemd service.')
