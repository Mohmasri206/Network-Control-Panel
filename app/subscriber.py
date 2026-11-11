"""Source-bound subscriber status and local contact tools; no admin data."""
import time
from flask import abort, jsonify, render_template, request


def status_data(p):
    state, mac, login, bypass, blocked, allowed = p.guest_info()
    policy = p.resolve_clients(state)[1].get(request.remote_addr, {})
    if policy.get('mac') != mac:
        raise ValueError('تغير اتصال الجهاز. حدّث الصفحة بعد لحظات.')
    blocked = bool(blocked or policy.get('blocked'))
    allowed = bool(policy.get('allowed'))
    if blocked: kind='blocked'
    elif state['hotspot'].get('key_only'): kind='key'
    elif bypass: kind='direct'
    elif not state['hotspot']['enabled']: kind='open'
    elif login: kind='trial' if login.get('trial') else 'account'
    else: kind='login'
    expires = 0
    if kind=='direct': expires=state['mac_rules'].get(mac,{}).get('direct_expires',0)
    elif login: expires=login['expires']
    return {'allowed':allowed,'kind':kind,'username':login['user'] if login and not login.get('trial') else '',
        'can_logout':bool(login),'started':login.get('started',0) if login else 0,
        'expires':expires,'server_now':int(time.time()),'ip':request.remote_addr,'mac':mac,
        'down':policy.get('down',0),'up':policy.get('up',0),
        'shared':bool(policy.get('trial_shared')),
        'pool_down':state['trial'].get('down',0),'pool_up':state['trial'].get('up',0)}


def attach(p):
    @p.app.before_request
    def subscriber_host():
        if request.path in ('/session-info','/status','/signout','/signed-out','/contact') and request.host.split(':')[0] != p.GATEWAY:
            abort(403)

    @p.app.get('/session-info')
    def session_info():
        try:
            with p.LOCK:
                return jsonify(status_data(p))
        except (ValueError,RuntimeError,OSError) as exc:
            return jsonify(error=str(exc)),503

    def status_page(signout=False,signed_out=False):
        try:
            with p.LOCK:
                return render_template('subscriber.html',client=status_data(p),signout=signout,signed_out=signed_out)
        except (ValueError,RuntimeError,OSError) as exc:
            return render_template('subscriber.html',client=None,error=str(exc),signout=signout,signed_out=signed_out),503

    @p.app.get('/status')
    def subscriber_status(): return status_page()

    @p.app.get('/signout')
    def signout_page(): return status_page(signout=True)

    @p.app.get('/signed-out')
    def signed_out_page(): return status_page(signed_out=True)

    @p.app.get('/contact')
    def contact_page():
        with p.LOCK:
            allowed=False
            try: allowed=p.guest_info()[-1]
            except (ValueError,RuntimeError,OSError): pass
            state=p.load_state()
            return render_template('contact.html',allowed=allowed,enabled=state['hotspot']['enabled'],
                                   key_only=state['hotspot'].get('key_only',False))
