"""MOH app launcher and authenticated password change via FileBrowser's API."""
import http.cookiejar
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from flask import abort, jsonify, render_template, request, session

FILES_URL = 'https://192.168.100.1:8444'


def change_files_password(current, new, certificate):
    # Trust only the installed local certificate, including its IP SAN.
    context = ssl.create_default_context(cafile=str(certificate))
    client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(context=context))
    encoded = urllib.parse.quote(current, safe='')
    login = urllib.request.Request(FILES_URL + '/api/auth/login?username=admin',
                                   data=b'', method='POST', headers={'X-Password': encoded})
    with client.open(login, timeout=8) as response:
        if response.status != 200:
            raise ValueError('تعذر تسجيل الدخول إلى الملفات')
    payload = json.dumps({'which': ['password'], 'data': {'password': new}}).encode()
    update = urllib.request.Request(FILES_URL + '/api/users?username=admin', data=payload,
                                    method='PATCH', headers={'X-Password': encoded,
                                    'Content-Type': 'application/json'})
    with client.open(update, timeout=8) as response:
        if response.status not in (200, 204):
            raise ValueError('تعذر حفظ كلمة المرور')


def attach(p):
    @p.app.get('/home')
    def app_home():
        return render_template('hub.html', page='home')

    @p.app.get('/apps/<page>')
    def app_page(page):
        if page not in {'files', 'desktop', 'password', 'system'}:
            abort(404)
        return render_template('hub.html', page=page)

    @p.app.post('/api/files/password')
    def files_password():
        if p.ROLE == 'guest' or not session.get('admin'):
            abort(403)
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            return jsonify(error='بيانات الطلب غير صحيحة'), 400
        current, new = value.get('current'), value.get('new')
        if not isinstance(current, str) or not current or len(current) > 128:
            return jsonify(error='أدخل كلمة مرور الملفات الحالية'), 400
        if not isinstance(new, str) or not 8 <= len(new) <= 128:
            return jsonify(error='كلمة المرور الجديدة من 8 إلى 128 محرفًا'), 400
        if new != value.get('repeat'):
            return jsonify(error='كلمتا المرور الجديدتان غير متطابقتين'), 400
        try:
            change_files_password(current, new, Path(p.BASE) / 'files-cert.pem')
        except urllib.error.HTTPError as exc:
            status = 429 if exc.code == 429 else 400
            return jsonify(error='طلبات كثيرة؛ انتظر قليلًا' if status == 429 else
                           'تحقق من كلمة مرور الملفات الحالية ثم حاول مجددًا'), status
        except (urllib.error.URLError, OSError, ValueError):
            return jsonify(error='تعذر الاتصال بخدمة الملفات؛ حاول لاحقًا'), 503
        # Never store or log passwords in MOH or its audit trail.
        return jsonify(ok=True, message='تم تغيير كلمة مرور الملفات. استخدم الجديدة عند الدخول.')
