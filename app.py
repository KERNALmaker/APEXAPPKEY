from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp, qrcode, io, base64, csv, json, os, hmac, hashlib, secrets
from io import StringIO
import jwt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from database import (db, License, User, Reseller, Coupon, ActivityLog, Heartbeat, Setting,
                      AppIntegrity, AppConfig, API_SECRET, DURATIONS, RESELLER_PRICES, 
                      generate_key, is_expired, time_remaining)

# ═══════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════
SECRET_KEY = os.getenv('SECRET_KEY', 'apex_secret_change_me_production')
JWT_SECRET = os.getenv('JWT_SECRET', 'apex_jwt_secret_change_me_production')
ADMIN_KEY = os.getenv('ADMIN_KEY', 'apex_admin_master_2026')
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///licenses.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
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
        'key': key, 'hwid': hwid,
        'iat': int(datetime.utcnow().timestamp()),
        'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    }, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try: return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except Exception: return None

class AdminUser(UserMixin):
    def __init__(self, u):
        self.id = u.id; self.username = u.username
        self.is_admin = u.is_admin; self.totp_enabled = u.totp_enabled

class ResellerUser(UserMixin):
    def __init__(self, r):
        self.id = r.id; self.username = r.username; self.credits = r.credits

@login_manager.user_loader
def load_user(uid):
    if str(uid).startswith('res_'):
        rid = int(str(uid).replace('res_', ''))
        r = Reseller.query.get(rid)
        return ResellerUser(r) if r else None
    else:
        u = User.query.get(int(uid))
        return AdminUser(u) if u else None

def log(action, details=''):
    db.session.add(ActivityLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action, details=details, ip_address=request.remote_addr
    ))
    db.session.commit()

# ═══════════════════════════════════════════════════
# HEALTH & MAINTENANCE
# ═══════════════════════════════════════════════════
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'APEX License Server',
                    'time': datetime.utcnow().isoformat()}), 200

@app.route('/ping', methods=['GET'])
def ping():
    return 'pong', 200

@app.before_request
def check_maintenance():
    if request.endpoint in ['maintenance', 'static', 'login', 'reseller_login',
                            'api_validate', 'api_heartbeat',
                            'api_integrity', 'api_button_action', 'api_app_config', 'health', 'ping']:
        return
    if request.path.startswith('/static/'):
        return
    if Setting.get('maintenance_mode', 'off') == 'on':
        if not (current_user.is_authenticated and isinstance(current_user, AdminUser) and current_user.is_admin):
            return redirect(url_for('maintenance'))

# ═══════════════════════════════════════════════════
# AUTH (ADMIN ONLY)
# ═══════════════════════════════════════════════════
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if isinstance(current_user, AdminUser): return redirect(url_for('dashboard'))
        else: return redirect(url_for('reseller_dashboard'))

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
def logout():
    logout_user()
    return redirect(url_for('login'))

# ═══════════════════════════════════════════════════
# ADMIN DASHBOARD
# ═══════════════════════════════════════════════════
@app.route('/dashboard')
@login_required
def dashboard():
    if not isinstance(current_user, AdminUser): return redirect(url_for('reseller_dashboard'))
    
    stats = {
        'total': License.query.count(),
        'active': License.query.filter_by(status='active').count(),
        'expired': License.query.filter_by(status='expired').count(),
        'frozen': License.query.filter_by(status='frozen').count(),
        'revoked': License.query.filter_by(status='revoked').count(),
        'pending': License.query.filter_by(status='pending').count(),
        'apps': AppIntegrity.query.filter_by(active=True).count(),
        'resellers': Reseller.query.count(),
        'coupons': Coupon.query.filter_by(is_used=False).count(),
    }
    logs = ActivityLog.query.order_by(ActivityLog.created_at.desc()).limit(20).all()
    return render_template('index.html', page='dashboard', stats=stats, logs=logs)

# ═══════════════════════════════════════════════════
# ADMIN: RESELLER MANAGEMENT
# ═══════════════════════════════════════════════════
@app.route('/admin_resellers', methods=['GET', 'POST'])
@login_required
def admin_resellers():
    if not isinstance(current_user, AdminUser): return redirect(url_for('reseller_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if Reseller.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        else:
            r = Reseller(username=username, password_hash=generate_password_hash(password))
            db.session.add(r); db.session.commit()
            flash('Reseller created successfully!', 'success')
        return redirect(url_for('admin_resellers'))

    resellers = Reseller.query.all()
    coupons = Coupon.query.order_by(Coupon.created_at.desc()).all()
    return render_template('index.html', page='resellers', resellers=resellers, coupons=coupons)

@app.route('/admin/delete_reseller/<int:rid>')
@login_required
def delete_reseller(rid):
    if not isinstance(current_user, AdminUser): return redirect(url_for('reseller_dashboard'))
    r = Reseller.query.get_or_404(rid)
    License.query.filter_by(reseller_id=r.id).delete()
    db.session.delete(r)
    db.session.commit()
    flash(f'Reseller {r.username} and their keys deleted.', 'success')
    return redirect(url_for('admin_resellers'))

@app.route('/admin/generate_coupon', methods=['POST'])
@login_required
def generate_coupon():
    if not isinstance(current_user, AdminUser): return redirect(url_for('reseller_dashboard'))
    credits = int(request.form.get('credits', 10))
    code = "CPN-" + secrets.token_hex(4).upper()
    c = Coupon(code=code, credits=credits)
    db.session.add(c); db.session.commit()
    flash(f'Coupon {code} ({credits} Credits) created!', 'success')
    return redirect(url_for('admin_resellers'))

@app.route('/admin/toggle_reseller/<int:rid>')
@login_required
def toggle_reseller(rid):
    if not isinstance(current_user, AdminUser): return redirect(url_for('reseller_dashboard'))
    r = Reseller.query.get_or_404(rid)
    r.is_active = not r.is_active
    db.session.commit()
    return redirect(url_for('admin_resellers'))

# ═══════════════════════════════════════════════════
# RESELLER LOGIN & DASHBOARD
# ═══════════════════════════════════════════════════
@app.route('/reseller_login', methods=['GET', 'POST'])
def reseller_login():
    if current_user.is_authenticated and isinstance(current_user, ResellerUser):
        return redirect(url_for('reseller_dashboard'))

    if request.method == 'POST':
        r = Reseller.query.filter_by(username=request.form.get('username', '')).first()
        pw = request.form.get('password', '')
        
        if not r or not check_password_hash(r.password_hash, pw):
            return render_template('reseller_login.html', error='Invalid credentials')
        if not r.is_active:
            return render_template('reseller_login.html', error='Account disabled')

        r.last_login = datetime.utcnow()
        db.session.commit()
        
        login_user(ResellerUser(r))
        return redirect(url_for('reseller_dashboard'))

    return render_template('reseller_login.html')

@app.route('/reseller_dashboard')
@login_required
def reseller_dashboard():
    if not isinstance(current_user, ResellerUser): return redirect(url_for('dashboard'))
    
    r = Reseller.query.get(current_user.id)
    my_keys = License.query.filter_by(reseller_id=r.id).order_by(License.created_at.desc()).all()
    
    # 🔥 ALAG FILE (reseller.html) USE KI HAI
    return render_template('reseller.html', reseller=r, keys=my_keys, prices=RESELLER_PRICES)

@app.route('/reseller_redeem', methods=['POST'])
@login_required
def reseller_redeem():
    if not isinstance(current_user, ResellerUser): return redirect(url_for('dashboard'))
    
    code = request.form.get('coupon_code', '').strip().upper()
    c = Coupon.query.filter_by(code=code, is_used=False).first()
    
    if c:
        c.is_used = True
        c.used_by = current_user.id
        r = Reseller.query.get(current_user.id)
        r.credits += c.credits
        db.session.commit()
        flash(f'Redeemed {c.credits} Credits!', 'success')
    else:
        flash('Invalid or used coupon code.', 'error')
        
    return redirect(url_for('reseller_dashboard'))

@app.route('/reseller_generate_key', methods=['POST'])
@login_required
def reseller_generate_key():
    if not isinstance(current_user, ResellerUser): return redirect(url_for('dashboard'))
    
    duration = request.form.get('duration')
    custom_prefix = request.form.get('custom_prefix', '').strip()
    
    r = Reseller.query.get(current_user.id)
    
    if duration not in RESELLER_PRICES:
        flash('Invalid duration selected.', 'error')
        return redirect(url_for('reseller_dashboard'))
        
    price_inr = RESELLER_PRICES[duration]['price']
    credits_needed = price_inr // 50
    
    if r.credits < credits_needed:
        flash('Not enough credits. Please redeem a coupon.', 'error')
        return redirect(url_for('reseller_dashboard'))
        
    r.credits -= credits_needed
    
    dur_seconds = DURATIONS.get(duration, 86400)
    lic = License(
        key=generate_key(custom_prefix),
        duration=duration,
        duration_seconds=dur_seconds,
        max_devices=1,
        created_by=f"Reseller_{r.username}",
        reseller_id=r.id
    )
    db.session.add(lic)
    db.session.commit()
    
    flash(f'Key generated: {lic.key} ({duration})', 'success')
    return redirect(url_for('reseller_dashboard'))

@app.route('/reseller/action/<action>/<int:lid>', methods=['POST'])
@login_required
def reseller_key_action(action, lid):
    if not isinstance(current_user, ResellerUser): return jsonify({'success': False}), 403
    lic = License.query.get_or_404(lid)
    
    if lic.reseller_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
    if action == 'revoke':
        lic.status = 'revoked'
    elif action == 'reset_hwid':
        lic.hwid = None
        lic.device_name = None
        lic.device_hwids = None
        lic.activated_at = None
        lic.expires_at = None
        lic.status = 'pending'
    elif action == 'delete':
        db.session.delete(lic)
        
    db.session.commit()
    return jsonify({'success': True})

# ═══════════════════════════════════════════════════
# ADMIN: LICENSES
# ═══════════════════════════════════════════════════
@app.route('/licenses')
@login_required
def licenses():
    if not isinstance(current_user, AdminUser): return redirect(url_for('reseller_dashboard'))
    
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', '')
    search = request.args.get('search', '')

    q = License.query
    if status: q = q.filter_by(status=status)
    if search: q = q.filter(db.or_(License.key.contains(search), License.hwid.contains(search), License.device_name.contains(search)))

    lics = q.order_by(License.created_at.desc()).paginate(page=page, per_page=50)

    now = datetime.utcnow()
    for l in lics.items:
        if l.duration == 'LIFETIME': l.remaining = "LIFETIME"
        elif l.expires_at:
            diff = (l.expires_at - now).total_seconds()
            if diff <= 0: l.remaining = "EXPIRED"
            else:
                d = int(diff // 86400); h = int((diff % 86400) // 3600); m = int((diff % 3600) // 60)
                if d > 0: l.remaining = f"{d}d {h}h {m}m"
                elif h > 0: l.remaining = f"{h}h {m}m"
                else: l.remaining = f"{m}m"
        else: l.remaining = "PENDING"

        l.devices = []
        if l.device_name:
            try:
                names = json.loads(l.device_name)
                l.devices = names if isinstance(names, list) else [l.device_name]
            except Exception:
                l.devices = [l.device_name]
        l.device_count = len(l.devices)

    return render_template('index.html', page='licenses', licenses=lics, status=status, search=search, durations=list(DURATIONS.keys()))

# ═══════════════════════════════════════════════════
# ADMIN: APP INTEGRITY, USERS, SETTINGS, LOGS
# ═══════════════════════════════════════════════════
@app.route('/apps')
@login_required
def apps_page():
    if not isinstance(current_user, AdminUser): return redirect(url_for('reseller_dashboard'))
    apps = AppIntegrity.query.order_by(AppIntegrity.registered_at.desc()).all()
    return render_template('index.html', page='apps', apps=apps)

@app.route('/api/apps/register', methods=['POST'])
@login_required
def register_app():
    if not isinstance(current_user, AdminUser): return jsonify({'success': False}), 403
    d = request.get_json() or {}
    required = ['package', 'apk_size', 'apk_sha256']
    for f in required:
        if f not in d: return jsonify({'success': False, 'error': f'missing {f}'}), 400

    app_db = AppIntegrity.query.filter_by(package=d['package']).first()
    if app_db is None:
        app_db = AppIntegrity(package=d['package'])
        db.session.add(app_db)

    app_db.version_name = d.get('version_name', app_db.version_name or '')
    app_db.version_code = int(d.get('version_code', app_db.version_code or 0))
    app_db.apk_size = int(d['apk_size'])
    app_db.apk_sha256 = d['apk_sha256']
    app_db.sig_sha256 = d.get('sig_sha256', '')
    app_db.min_version_code = int(d.get('min_version_code', 0))
    app_db.active = True
    db.session.commit()
    log('app_register', d['package'])
    return jsonify({'success': True})

@app.route('/api/apps/<action>/<int:aid>', methods=['POST'])
@login_required
def app_action(action, aid):
    if not isinstance(current_user, AdminUser): return jsonify({'success': False}), 403
    a = AppIntegrity.query.get_or_404(aid)
    if action == 'delete': db.session.delete(a)
    elif action == 'toggle': a.active = not a.active
    db.session.commit(); log(f'app_{action}', a.package)
    return jsonify({'success': True})

@app.route('/users')
@login_required
def users():
    if not isinstance(current_user, AdminUser): return redirect(url_for('reseller_dashboard'))
    return render_template('index.html', page='users', users=User.query.all())

@app.route('/logs')
@login_required
def logs_page():
    if not isinstance(current_user, AdminUser): return redirect(url_for('reseller_dashboard'))
    page = request.args.get('page', 1, type=int)
    logs = ActivityLog.query.order_by(ActivityLog.created_at.desc()).paginate(page=page, per_page=100)
    return render_template('index.html', page='logs', logs=logs)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if not isinstance(current_user, AdminUser): return redirect(url_for('reseller_dashboard'))
    if request.method == 'POST':
        Setting.set('maintenance_message', request.form.get('maintenance_message', ''))
        config = AppConfig.get_config()
        config.app_name = request.form.get('app_name', config.app_name)
        config.telegram_channel = request.form.get('telegram_channel', config.telegram_channel)
        config.telegram_developer = request.form.get('telegram_developer', config.telegram_developer)
        db.session.commit()
        return redirect(url_for('settings'))
    config = AppConfig.get_config()
    return render_template('index.html', page='settings',
        maintenance_mode=Setting.get('maintenance_mode', 'off'),
        maintenance_message=Setting.get('maintenance_message', ''),
        app_name=config.app_name, telegram_channel=config.telegram_channel, telegram_developer=config.telegram_developer
    )

@app.route('/api/maintenance/toggle', methods=['POST'])
@login_required
def toggle_maintenance():
    if not isinstance(current_user, AdminUser): return jsonify({'success': False}), 403
    cur = Setting.get('maintenance_mode', 'off')
    new = 'off' if cur == 'on' else 'on'
    Setting.set('maintenance_mode', new)
    log('maintenance_toggle', new)
    return jsonify({'success': True, 'mode': new})

@app.route('/maintenance')
def maintenance():
    return render_template('index.html', page='maintenance', message=Setting.get('maintenance_message', 'Under maintenance'))

# ═══════════════════════════════════════════════════
# ADMIN: LICENSE GENERATE / ACTIONS
# ═══════════════════════════════════════════════════
@app.route('/api/license/generate', methods=['POST'])
@login_required
def generate():
    if not isinstance(current_user, AdminUser): return jsonify({'success': False}), 403
    d = request.get_json()
    count = min(int(d.get('count', 1)), 10000)
    dur = d.get('duration', '1D')
    sec = int(d.get('custom_seconds', 0)) if dur == 'CUSTOM' else DURATIONS.get(dur, 0)
    max_dev = int(d.get('max_devices', 1))
    custom_prefix = d.get('custom_prefix', '').strip()

    keys = []
    for _ in range(count):
        lic = License(key=generate_key(custom_prefix), duration=dur, duration_seconds=sec, max_devices=max_dev, created_by=current_user.username)
        db.session.add(lic); keys.append(lic.key)

    db.session.commit()
    log('bulk_generate', f'{count} keys ({dur})')
    return jsonify({'success': True, 'count': count, 'keys': keys})

@app.route('/api/license/<action>/<int:lid>', methods=['POST'])
@login_required
def lic_action(action, lid):
    if not isinstance(current_user, AdminUser): return jsonify({'success': False}), 403
    lic = License.query.get_or_404(lid)
    if action == 'revoke': lic.status = 'revoked'
    elif action == 'reset_hwid':
        lic.hwid = None; lic.device_name = None; lic.device_hwids = None; lic.activated_at = None; lic.expires_at = None; lic.status = 'pending'
    elif action == 'freeze': lic.status = 'active' if lic.status == 'frozen' else 'frozen'
    elif action == 'delete': db.session.delete(lic)
    db.session.commit(); log(f'license_{action}', lic.key)
    return jsonify({'success': True})

@app.route('/api/license/export')
@login_required
def export():
    if not isinstance(current_user, AdminUser): return jsonify({'error': 'Unauthorized'}), 403
    fmt = request.args.get('format', 'json')
    data = [l.to_dict() for l in License.query.all()]
    if fmt == 'csv':
        si = StringIO()
        if data:
            w = csv.DictWriter(si, fieldnames=data[0].keys()); w.writeheader(); w.writerows(data)
        return si.getvalue(), 200, {'Content-Type': 'text/csv'}
    return jsonify(data)

# ═══════════════════════════════════════════════════
# CLIENT APIs
# ═══════════════════════════════════════════════════
@app.route('/api/integrity', methods=['POST'])
def api_integrity():
    d = request.get_json()
    if not d: return jsonify({'error': 'No data'}), 400
    if d.get('secret') != API_SECRET: return jsonify({'error': 'Invalid secret'}), 403
    pkg = (d.get('package') or '').strip()
    if not pkg: return jsonify({'error': 'Missing package'}), 400
    record = AppIntegrity.query.filter_by(package=pkg, active=True).first()
    if not record: return jsonify({'data': encrypt_response({'valid': False, 'reason': 'UNKNOWN_PACKAGE'})})
    try:
        client_size = int(d.get('apk_size', -1))
        client_apk_sha = (d.get('apk_sha256') or '').strip().lower()
    except Exception: return jsonify({'data': encrypt_response({'valid': False, 'reason': 'BAD_PAYLOAD'})})
    if client_size != record.apk_size: return jsonify({'data': encrypt_response({'valid': False, 'reason': 'SIZE_MISMATCH'})})
    if client_apk_sha != record.apk_sha256.lower(): return jsonify({'data': encrypt_response({'valid': False, 'reason': 'APK_HASH_MISMATCH'})})
    return jsonify({'data': encrypt_response({'valid': True, 'reason': 'OK'})})

@app.route('/api/app_config', methods=['POST'])
def api_app_config():
    d = request.get_json()
    if not d or d.get('secret') != API_SECRET: return jsonify({'error': 'Invalid'}), 403
    pkg = (d.get('package') or '').strip()
    if pkg:
        record = AppIntegrity.query.filter_by(package=pkg, active=True).first()
        if record:
            try:
                if int(d.get('apk_size', -1)) != record.apk_size: return jsonify({'data': encrypt_response({'valid': False, 'reason': 'APK_MODIFIED'})})
                if (d.get('apk_sha256') or '').strip().lower() != record.apk_sha256.lower(): return jsonify({'data': encrypt_response({'valid': False, 'reason': 'APK_MODIFIED'})})
            except Exception: return jsonify({'data': encrypt_response({'valid': False, 'reason': 'BAD_PAYLOAD'})})
    config = AppConfig.get_config()
    return jsonify({'data': encrypt_response({'valid': True, 'app_name': config.app_name, 'channel_link': config.telegram_channel, 'dev_link': config.telegram_developer})})

@app.route('/api/validate', methods=['POST'])
def api_validate():
    d = request.get_json()
    if not d: return jsonify({'error': 'No data'}), 400
    if d.get('secret') != API_SECRET: return jsonify({'error': 'Invalid secret'}), 403
    pkg = (d.get('package') or '').strip()
    if pkg:
        record = AppIntegrity.query.filter_by(package=pkg, active=True).first()
        if record:
            try:
                if int(d.get('apk_size', -1)) != record.apk_size: return jsonify({'data': encrypt_response({'valid': False, 'reason': 'APK_MODIFIED'})})
                if (d.get('apk_sha256') or '').strip().lower() != record.apk_sha256.lower(): return jsonify({'data': encrypt_response({'valid': False, 'reason': 'APK_MODIFIED'})})
            except Exception: return jsonify({'data': encrypt_response({'valid': False, 'reason': 'BAD_PAYLOAD'})})
    key = d.get('key', '').strip()
    hwid = d.get('hwid', '').strip()
    dev = d.get('device_name', '')
    if not key or not hwid: return jsonify({'error': 'Missing'}), 400
    if Setting.get('maintenance_mode', 'off') == 'on': return jsonify({'data': encrypt_response({'valid': False, 'reason': 'MAINTENANCE'})})
    lic = License.query.filter_by(key=key).first()
    if not lic: return jsonify({'data': encrypt_response({'valid': False, 'reason': 'INVALID_KEY'})})
    if lic.status == 'revoked': return jsonify({'data': encrypt_response({'valid': False, 'reason': 'REVOKED'})})
    if lic.status == 'frozen': return jsonify({'data': encrypt_response({'valid': False, 'reason': 'FROZEN'})})
    if lic.status == 'expired' or is_expired(lic):
        lic.status = 'expired'; db.session.commit()
        return jsonify({'data': encrypt_response({'valid': False, 'reason': 'EXPIRED'})})
    if lic.ip_lock and lic.ip_lock != request.remote_addr: return jsonify({'data': encrypt_response({'valid': False, 'reason': 'IP_LOCKED'})})
    device_hwids = []
    if lic.device_hwids:
        try: device_hwids = json.loads(lic.device_hwids)
        except Exception: device_hwids = []
    device_names = []
    if lic.device_name:
        try:
            device_names = json.loads(lic.device_name)
            if not isinstance(device_names, list): device_names = [lic.device_name] if lic.device_name else []
        except Exception: device_names = [lic.device_name] if lic.device_name else []
    if hwid in device_hwids: pass
    else:
        if len(device_hwids) >= lic.max_devices:
            return jsonify({'data': encrypt_response({'valid': False, 'reason': 'MAX_DEVICES', 'message': f'Max {lic.max_devices} device(s) allowed.'})})
        device_hwids.append(hwid); device_names.append(dev if dev else "Unknown Device")
        lic.device_hwids = json.dumps(device_hwids); lic.device_name = json.dumps(device_names)
        if not lic.activated_at:
            lic.activated_at = datetime.utcnow(); lic.expires_at = datetime.utcnow() + timedelta(seconds=lic.duration_seconds); lic.status = 'active'
        if not lic.hwid: lic.hwid = hwid
    lic.last_heartbeat = datetime.utcnow()
    db.session.add(Heartbeat(license_key=key, hwid=hwid, ip_address=request.remote_addr))
    db.session.commit()
    token = generate_token(key, hwid)
    return jsonify({'data': encrypt_response({'valid': True, 'token': token, 'status': lic.status, 'expires_at': lic.expires_at.strftime('%Y-%m-%dT%H:%M:%S') if lic.expires_at else None, 'time_remaining': time_remaining(lic), 'max_devices': lic.max_devices, 'registered_devices': len(device_hwids)})})

@app.route('/api/heartbeat', methods=['POST'])
def api_heartbeat():
    d = request.get_json()
    if not d or d.get('secret') != API_SECRET: return jsonify({'error': 'Invalid'}), 403
    payload = verify_token(d.get('token', ''))
    if not payload or payload.get('hwid') != d.get('hwid', ''): return jsonify({'data': encrypt_response({'valid': False, 'reason': 'TOKEN_EXPIRED'})})
    lic = License.query.filter_by(key=payload.get('key')).first()
    if not lic or lic.status != 'active' or is_expired(lic): return jsonify({'data': encrypt_response({'valid': False, 'reason': 'EXPIRED'})})
    lic.last_heartbeat = datetime.utcnow(); db.session.commit()
    return jsonify({'data': encrypt_response({'valid': True, 'time_remaining': time_remaining(lic)})})

@app.route('/api/button_action', methods=['POST'])
def api_button_action():
    d = request.get_json()
    if not d or d.get('secret') != API_SECRET: return jsonify({'error': 'Invalid'}), 403
    payload = verify_token(d.get('token', ''))
    if not payload or payload.get('hwid') != d.get('hwid', ''): return jsonify({'data': encrypt_response({'valid': False, 'reason': 'TOKEN_EXPIRED'})})
    lic = License.query.filter_by(key=payload.get('key')).first()
    if not lic or lic.status != 'active' or is_expired(lic): return jsonify({'data': encrypt_response({'valid': False, 'reason': 'EXPIRED'})})
    action = d.get('action', '')
    if action in ['inject', 'bypass']:
        magic_sig = hmac.new(b"apex_super_secret_key_xyz", f"{lic.key}:{d.get('hwid')}:{action}".encode(), hashlib.sha256).hexdigest()
        return jsonify({'data': encrypt_response({'valid': True, 'action': action.upper() + '_READY', 'sig': magic_sig[:16]})})
    return jsonify({'data': encrypt_response({'valid': False, 'reason': 'UNKNOWN_ACTION'})})

# ═══════════════════════════════════════════════════
# INIT DB
# ═══════════════════════════════════════════════════
with app.app_context():
    try:
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            db.session.add(User(username='admin', password_hash=generate_password_hash('apex_admin_2026'), is_admin=True))
            db.session.commit()
            print("[+] Admin: admin / apex_admin_2026")
        AppConfig.get_config()
        print("[+] Database initialized")
    except Exception as e:
        print(f"[!] DB init error: {e}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
