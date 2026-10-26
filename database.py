from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib, secrets, string

db = SQLAlchemy()

# ═══════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════
API_SECRET = 'apex_api_secret_2026'

DURATIONS = {
    '1H': 3600, '6H': 21600, '12H': 43200,
    '1D': 86400, '3D': 259200, '7D': 604800,
    '30D': 2592000, '90D': 7776000,
    'LIFETIME': 9999999999,
}

# 🔥 RESELLER RATES (1 Credit = ₹50)
RESELLER_PRICES = {
    '1D': {'price': 50, 'credits': 1},
    '3D': {'price': 150, 'credits': 3},
    '7D': {'price': 250, 'credits': 5},
    '15D': {'price': 400, 'credits': 8},
    '30D': {'price': 600, 'credits': 12},
}

# ═══════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════
class License(db.Model):
    __tablename__ = 'licenses'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    hwid = db.Column(db.String(64), nullable=True, index=True)
    duration = db.Column(db.String(32), nullable=False)
    duration_seconds = db.Column(db.Integer, nullable=False)
    max_devices = db.Column(db.Integer, default=1)
    status = db.Column(db.String(16), default='pending', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    activated_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    last_heartbeat = db.Column(db.DateTime, nullable=True)
    device_name = db.Column(db.Text, nullable=True)
    device_hwids = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.String(64), nullable=True)
    reseller_id = db.Column(db.Integer, nullable=True)

    def time_remaining(self):
        if self.duration == 'LIFETIME': return "LIFETIME"
        if not self.expires_at: return "PENDING"
        diff = (self.expires_at - datetime.utcnow()).total_seconds()
        if diff <= 0: return "EXPIRED"
        d = int(diff // 86400); h = int((diff % 86400) // 3600); m = int((diff % 3600) // 60)
        if d > 0: return f"{d}d {h}h {m}m"
        if h > 0: return f"{h}h {m}m"
        return f"{m}m"

    def to_dict(self):
        return {
            'id': self.id, 'key': self.key, 'hwid': self.hwid,
            'duration': self.duration, 'status': self.status,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'device_name': self.device_name,
            'remaining': self.time_remaining(),
        }

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=True)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime, nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Reseller(db.Model):
    __tablename__ = 'resellers'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    credits = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

class Coupon(db.Model):
    __tablename__ = 'coupons'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False)
    credits = db.Column(db.Integer, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    used_by = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Setting(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)

    @staticmethod
    def get(key, default=None):
        s = Setting.query.filter_by(key=key).first()
        return s.value if s else default

    @staticmethod
    def set(key, value):
        s = Setting.query.filter_by(key=key).first()
        if s: s.value = value
        else: db.session.add(Setting(key=key, value=value))
        db.session.commit()

class AppConfig(db.Model):
    __tablename__ = 'app_config'
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(64), default='APEX V2')
    telegram_channel = db.Column(db.String(128), default='https://t.me/your_channel')
    telegram_developer = db.Column(db.String(128), default='https://t.me/your_dev')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @staticmethod
    def get_config():
        config = AppConfig.query.first()
        if not config:
            config = AppConfig(
                app_name='APEX V2',
                telegram_channel='https://t.me/your_channel',
                telegram_developer='https://t.me/your_dev'
            )
            db.session.add(config)
            db.session.commit()
        return config

# 🔥 APP INTEGRITY MODEL (Multiple Records Allowed)
class AppIntegrity(db.Model):
    __tablename__ = 'app_integrity'
    id = db.Column(db.Integer, primary_key=True)
    package = db.Column(db.String(128), nullable=False, index=True) # 🔥 Not Unique
    version_name = db.Column(db.String(64), nullable=True)
    version_code = db.Column(db.Integer, default=0)
    apk_size = db.Column(db.BigInteger, nullable=False)
    apk_sha256 = db.Column(db.String(128), nullable=False)
    sig_sha256 = db.Column(db.String(128), nullable=True)
    min_version_code = db.Column(db.Integer, default=0)
    active = db.Column(db.Boolean, default=True)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ═══════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════
def generate_key(custom_prefix=None):
    abc = string.ascii_uppercase + string.digits
    if custom_prefix:
        clean_prefix = "".join(e for e in custom_prefix if e.isalnum()).upper()
        rand_part = ''.join(secrets.choice(abc) for _ in range(4))
        return f"APEX-{clean_prefix}-{rand_part}"
    else:
        parts = [''.join(secrets.choice(abc) for _ in range(4)) for _ in range(4)]
        return f"APEX-{'-'.join(parts)}"

def is_expired(lic):
    if lic.duration == 'LIFETIME': return False
    if not lic.expires_at: return False
    return datetime.utcnow() > lic.expires_at

def time_remaining(lic):
    return lic.time_remaining()
