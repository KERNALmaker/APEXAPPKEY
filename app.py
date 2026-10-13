from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp, qrcode, io, base64, csv, json
from io import StringIO
import jwt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from database import (db, License, User, ActivityLog, Heartbeat, Setting,
                      API_SECRET, DURATIONS, generate_key, is_expired,
                      time_remaining)

# ═══════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════
JWT_SECRET = 'apex_jwt_secret_change_me_production'
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'apex_secret_change_me_production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///licenses.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# ═══════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════
def encrypt_response(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(json.dumps(data).encode(), AES.block_size)
    return base64.b64encode(cipher.encrypt(padded)).decode()


def generate_token(key, hwid):
    return jwt.encode({
        'key': key,
        'hwid': hwid,
        'iat': int(datetime.utcnow().timestamp()),
        'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    }, JWT_SECRET, algorithm='HS256')


def verify_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except:
        return None


# ═══════════════════════════════════════════════════
# USER CLASS
# ═══════════════════════════════════════════════════
class AdminUser(UserMixin):
    def __init__(self, u):
        self.id = u.id
        self.username = u.username
        self.is_admin = u.is_admin
        self.totp_enabled = u.totp_enabled


@login_manager.user_loader
def load_user(uid):
    u = User.query.get(int(uid))
    return AdminUser(u) if u else None


def log(action, details=''):
    db.session.add(ActivityLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action, details=details, ip_address=request.remote_addr
    ))
    db.session.commit()


# ═══════════════════════════════════════════════════
# HEALTH CHECK (UptimeRobot)
# ═══════════════════════════════════════════════════
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'service': 'APEX License Server',
        'time': datetime.utcnow().isoformat()
    }), 200


@app.route('/ping', methods=['GET'])
def ping():
    return 'pong', 200


# ═══════════════════════════════════════════════════
# MAINTENANCE CHECK
# ═══════════════════════════════════════════════════
@app.before_request
def check_maintenance():
    if request.endpoint in ['maintenance', 'static', 'login',
                            'api_validate', 'api_heartbeat',
                            'health', 'ping']:
        return
    if request.path.startswith('/static/'):
        return
    if request.path in ['/health', '/ping']:
        return
    if Setting.get('maintenance_mode', 'off') == 'on':
        if not (current_user.is_authenticated and current_user.is_admin):
            return redirect(url_for('maintenance'))


# ═══════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        u = User.query.filter_by(username=request.form.get('username', '')).first()
        pw = request.form.get('password', '')
        code = request.form.get('totp_code', '')

        if not u or not check_password_hash(u.password_hash, pw):
            if u:
                u.login_attempts += 1
                if u.login_attempts >= 5:
                    u.locked_until = datetime.utcnow() + timedelta(minutes=15)
                db.session.commit()
            log('login_failed', request.form.get('username', ''))
            return render_template('index.html', page='login', error='Invalid credentials')

        if u.locked_until and u.locked_until > datetime.utcnow():
            return render_template('index.html', page='login', error='Account locked')

        if u.totp_enabled:
            if not code:
                return render_template('index.html', page='login', require_2fa=True)
            if not pyotp.TOTP(u.totp_secret).verify(code, valid_window=1):
                return render_template('index.html', page='login', require_2fa=True, error='Invalid 2FA')

        u.login_attempts = 0
        u.locked_until = None
        u.last_login = datetime.utcnow()
        db.session.commit()
        login_user(AdminUser(u))
        log('login_success')
        return redirect(url_for('dashboard'))

    return render_template('index.html', page='login')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ═══════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════
@app.route('/dashboard')
@login_required
def dashboard():
    stats = {
        'total': License.query.count(),
        'active': License.query.filter_by(status='active').count(),
        'expired': License.query.filter_by(status='expired').count(),
        'frozen': License.query.filter_by(status='frozen').count(),
        'revoked': License.query.filter_by(status='revoked').count(),
        'pending': License.query.filter_by(status='pending').count(),
    }
    logs = ActivityLog.query.order_by(ActivityLog.created_at.desc()).limit(20).all()
    return render_template('index.html', page='dashboard', stats=stats, logs=logs)


# ═══════════════════════════════════════════════════
# LICENSES PAGE
# ═══════════════════════════════════════════════════
@app.route('/licenses')
@login_required
def licenses():
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', '')
    search = request.args.get('search', '')

    q = License.query
    if status:
        q = q.filter_by(status=status)
    if search:
        q = q.filter(db.or_(
            License.key.contains(search),
            License.hwid.contains(search),
            License.device_name.contains(search)
        ))

    lics = q.order_by(License.created_at.desc()).paginate(page=page, per_page=50)

    now = datetime.utcnow()
    for l in lics.items:
        if l.duration == 'LIFETIME':
            l.remaining = "LIFETIME"
        elif l.expires_at:
            diff = (l.expires_at - now).total_seconds()
            if diff <= 0:
                l.remaining = "EXPIRED"
            else:
                d = int(diff // 86400)
                h = int((diff % 86400) // 3600)
                m = int((diff % 3600) // 60)
                if d > 0:
                    l.remaining = f"{d}d {h}h {m}m"
                elif h > 0:
                    l.remaining = f"{h}h {m}m"
                else:
                    l.remaining = f"{m}m"
        else:
            l.remaining = "PENDING"

    return render_template('index.html', page='licenses', licenses=lics,
                          status=status, search=search, durations=list(DURATIONS.keys()))


# ═══════════════════════════════════════════════════
# USERS PAGE
# ═══════════════════════════════════════════════════
@app.route('/users')
@login_required
def users():
    return render_template('index.html', page='users', users=User.query.all())


# ═══════════════════════════════════════════════════
# LOGS PAGE
# ═══════════════════════════════════════════════════
@app.route('/logs')
@login_required
def logs_page():
    page = request.args.get('page', 1, type=int)
    logs = ActivityLog.query.order_by(ActivityLog.created_at.desc()).paginate(page=page, per_page=100)
    return render_template('index.html', page='logs', logs=logs)


# ═══════════════════════════════════════════════════
# SETTINGS PAGE
# ═══════════════════════════════════════════════════
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        Setting.set('maintenance_message', request.form.get('maintenance_message', ''))
        return redirect(url_for('settings'))
    return render_template('index.html', page='settings',
        maintenance_mode=Setting.get('maintenance_mode', 'off'),
        maintenance_message=Setting.get('maintenance_message', ''))


# ═══════════════════════════════════════════════════
# MAINTENANCE
# ═══════════════════════════════════════════════════
@app.route('/api/maintenance/toggle', methods=['POST'])
@login_required
def toggle_maintenance():
    cur = Setting.get('maintenance_mode', 'off')
    new = 'off' if cur == 'on' else 'on'
    Setting.set('maintenance_mode', new)
    log('maintenance_toggle', new)
    return jsonify({'success': True, 'mode': new})


@app.route('/maintenance')
def maintenance():
    return render_template('index.html', page='maintenance',
        message=Setting.get('maintenance_message', 'Under maintenance'))


# ═══════════════════════════════════════════════════
# LICENSE GENERATE
# ═══════════════════════════════════════════════════
@app.route('/api/license/generate', methods=['POST'])
@login_required
def generate():
    d = request.get_json()
    count = min(int(d.get('count', 1)), 10000)
    dur = d.get('duration', '1D')
    sec = int(d.get('custom_seconds', 0)) if dur == 'CUSTOM' else DURATIONS.get(dur, 0)

    keys = []
    for _ in range(count):
        lic = License(
            key=generate_key(), duration=dur, duration_seconds=sec,
            max_devices=int(d.get('max_devices', 1)),
            ip_lock=d.get('ip_lock') or None,
            country_lock=d.get('country_lock') or None,
            app_version_lock=d.get('app_version_lock') or None,
            created_by=current_user.username
        )
        db.session.add(lic)
        keys.append(lic.key)

    db.session.commit()
    log('bulk_generate', f'{count} keys ({dur})')
    return jsonify({'success': True, 'count': count, 'keys': keys})


# ═══════════════════════════════════════════════════
# LICENSE ACTIONS
# ═══════════════════════════════════════════════════
@app.route('/api/license/<action>/<int:lid>', methods=['POST'])
@login_required
def lic_action(action, lid):
    lic = License.query.get_or_404(lid)

    if action == 'revoke':
        lic.status = 'revoked'
    elif action == 'reset_hwid':
        lic.hwid = None
        lic.device_name = None
        lic.activated_at = None
        lic.expires_at = None
        lic.status = 'pending'
    elif action == 'freeze':
        lic.status = 'active' if lic.status == 'frozen' else 'frozen'
    elif action == 'delete':
        db.session.delete(lic)

    db.session.commit()
    log(f'license_{action}', lic.key)
    return jsonify({'success': True})


# ═══════════════════════════════════════════════════
# EXPORT
# ═══════════════════════════════════════════════════
@app.route('/api/license/export')
@login_required
def export():
    fmt = request.args.get('format', 'json')
    data = [l.to_dict() for l in License.query.all()]

    if fmt == 'csv':
        si = StringIO()
        if data:
            w = csv.DictWriter(si, fieldnames=data[0].keys())
            w.writeheader()
            w.writerows(data)
        return si.getvalue(), 200, {'Content-Type': 'text/csv'}
    return jsonify(data)


# ═══════════════════════════════════════════════════
# 2FA SETUP
# ═══════════════════════════════════════════════════
@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    u = User.query.get(current_user.id)

    if request.method == 'POST':
        if pyotp.TOTP(u.totp_secret).verify(request.form.get('totp_code', '')):
            u.totp_enabled = True
            db.session.commit()
            return redirect(url_for('dashboard'))

    if not u.totp_secret:
        u.totp_secret = pyotp.random_base32()
        db.session.commit()

    uri = pyotp.TOTP(u.totp_secret).provisioning_uri(u.username, issuer_name='APEX')
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    buf.seek(0)

    return render_template('index.html', page='2fa',
        secret=u.totp_secret, qr=base64.b64encode(buf.read()).decode())


# ═══════════════════════════════════════════════════
# CLIENT API — VALIDATE
# ═══════════════════════════════════════════════════
@app.route('/api/validate', methods=['POST'])
def api_validate():
    d = request.get_json()
    if not d:
        return jsonify({'error': 'No data'}), 400

    if d.get('secret') != API_SECRET:
        return jsonify({'error': 'Invalid secret'}), 403

    key = d.get('key', '').strip()
    hwid = d.get('hwid', '').strip()
    dev = d.get('device_name', '')

    if not key or not hwid:
        return jsonify({'error': 'Missing'}), 400

    if Setting.get('maintenance_mode', 'off') == 'on':
        return jsonify({'data': encrypt_response({
            'valid': False, 'reason': 'MAINTENANCE'
        })})

    lic = License.query.filter_by(key=key).first()
    if not lic:
        return jsonify({'data': encrypt_response({'valid': False, 'reason': 'INVALID_KEY'})})

    if lic.status == 'revoked':
        return jsonify({'data': encrypt_response({'valid': False, 'reason': 'REVOKED'})})
    if lic.status == 'frozen':
        return jsonify({'data': encrypt_response({'valid': False, 'reason': 'FROZEN'})})
    if lic.status == 'expired' or is_expired(lic):
        lic.status = 'expired'
        db.session.commit()
        return jsonify({'data': encrypt_response({'valid': False, 'reason': 'EXPIRED'})})

    if lic.ip_lock and lic.ip_lock != request.remote_addr:
        return jsonify({'data': encrypt_response({'valid': False, 'reason': 'IP_LOCKED'})})

    if lic.hwid and lic.hwid != hwid and lic.max_devices <= 1:
        return jsonify({'data': encrypt_response({'valid': False, 'reason': 'HWID_MISMATCH'})})

    if not lic.hwid:
        lic.hwid = hwid
        lic.device_name = dev
        lic.activated_at = datetime.utcnow()
        lic.expires_at = datetime.utcnow() + timedelta(seconds=lic.duration_seconds)
        lic.status = 'active'

    lic.last_heartbeat = datetime.utcnow()
    db.session.add(Heartbeat(license_key=key, hwid=hwid, ip_address=request.remote_addr))
    db.session.commit()

    token = generate_token(key, hwid)

    return jsonify({'data': encrypt_response({
        'valid': True,
        'token': token,
        'status': lic.status,
        'expires_at': lic.expires_at.strftime('%Y-%m-%dT%H:%M:%S') if lic.expires_at else None,
        'time_remaining': time_remaining(lic)
    })})


# ═══════════════════════════════════════════════════
# CLIENT API — HEARTBEAT
# ═══════════════════════════════════════════════════
@app.route('/api/heartbeat', methods=['POST'])
def api_heartbeat():
    d = request.get_json()
    if not d:
        return jsonify({'error': 'No data'}), 400

    if d.get('secret') != API_SECRET:
        return jsonify({'error': 'Invalid'}), 403

    token = d.get('token', '')
    hwid = d.get('hwid', '')

    payload = verify_token(token)
    if not payload:
        return jsonify({'data': encrypt_response({'valid': False, 'reason': 'TOKEN_EXPIRED'})})

    if payload.get('hwid') != hwid:
        return jsonify({'data': encrypt_response({'valid': False, 'reason': 'HWID_MISMATCH'})})

    lic = License.query.filter_by(key=payload.get('key')).first()
    if not lic or lic.status != 'active' or is_expired(lic):
        return jsonify({'data': encrypt_response({'valid': False, 'reason': 'EXPIRED'})})

    lic.last_heartbeat = datetime.utcnow()
    db.session.commit()

    return jsonify({'data': encrypt_response({
        'valid': True,
        'time_remaining': time_remaining(lic)
    })})


# ═══════════════════════════════════════════════════
# INIT DB (Runs on import - for Gunicorn)
# ═══════════════════════════════════════════════════
with app.app_context():
    try:
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            db.session.add(User(
                username='admin',
                password_hash=generate_password_hash('apex_admin_2026'),
                is_admin=True
            ))
            db.session.commit()
            print("[+] Admin: admin / apex_admin_2026")
        Setting.set('maintenance_mode', Setting.get('maintenance_mode', 'off'))
        Setting.set('maintenance_message', Setting.get('maintenance_message',
                    'System under maintenance. Please try again later.'))
        print("[+] Database initialized")
    except Exception as e:
        print(f"[!] DB init error: {e}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
