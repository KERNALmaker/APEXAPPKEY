from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from datetime import datetime
from database import db, Reseller, License, Coupon, DURATIONS, RESELLER_PRICES, generate_key

reseller_bp = Blueprint('reseller', __name__)

# Custom User Class for Reseller
class ResellerUser:
    def __init__(self, r):
        self.id = f"res_{r.id}" # Prefixed to avoid clash with Admin ID
        self.username = r.username
        self.credits = r.credits
        self.is_active = True
        self.is_authenticated = True
        self.is_anonymous = False
        
    def get_id(self):
        return str(self.id)

# ═══════════════════════════════════════════════════
# RESELLER LOGIN
# ═══════════════════════════════════════════════════
@reseller_bp.route('/login', methods=['GET', 'POST'])
def reseller_login():
    if current_user.is_authenticated:
        return redirect(url_for('reseller.dashboard'))

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
        return redirect(url_for('reseller.dashboard'))

    return render_template('reseller_login.html')

# ═══════════════════════════════════════════════════
# RESELLER DASHBOARD
# ═══════════════════════════════════════════════════
@reseller_bp.route('/dashboard')
@login_required
def dashboard():
    # Check if user is Reseller
    if not str(current_user.id).startswith('res_'):
        return redirect(url_for('dashboard')) # Redirect to Admin
        
    rid = int(str(current_user.id).replace('res_', ''))
    r = Reseller.query.get(rid)
    my_keys = License.query.filter_by(reseller_id=r.id).order_by(License.created_at.desc()).all()
    
    return render_template('reseller_dashboard.html', reseller=r, keys=my_keys, prices=RESELLER_PRICES)

# ═══════════════════════════════════════════════════
# REDEEM COUPON
# ═══════════════════════════════════════════════════
@reseller_bp.route('/redeem', methods=['POST'])
@login_required
def redeem():
    if not str(current_user.id).startswith('res_'):
        return redirect(url_for('dashboard'))
        
    code = request.form.get('coupon_code', '').strip().upper()
    c = Coupon.query.filter_by(code=code, is_used=False).first()
    
    if c:
        c.is_used = True
        c.used_by = current_user.id
        rid = int(str(current_user.id).replace('res_', ''))
        r = Reseller.query.get(rid)
        r.credits += c.credits
        db.session.commit()
        flash(f'Redeemed {c.credits} Credits!', 'success')
    else:
        flash('Invalid or used coupon code.', 'error')
        
    return redirect(url_for('reseller.dashboard'))

# ═══════════════════════════════════════════════════
# GENERATE KEY
# ═══════════════════════════════════════════════════
@reseller_bp.route('/generate_key', methods=['POST'])
@login_required
def generate_key_route():
    if not str(current_user.id).startswith('res_'):
        return redirect(url_for('dashboard'))
    
    duration = request.form.get('duration')
    custom_prefix = request.form.get('custom_prefix', '').strip()
    
    rid = int(str(current_user.id).replace('res_', ''))
    r = Reseller.query.get(rid)
    
    if duration not in RESELLER_PRICES:
        flash('Invalid duration selected.', 'error')
        return redirect(url_for('reseller.dashboard'))
        
    price_inr = RESELLER_PRICES[duration]['price']
    credits_needed = price_inr // 50
    
    if r.credits < credits_needed:
        flash('Not enough credits. Please redeem a coupon.', 'error')
        return redirect(url_for('reseller.dashboard'))
        
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
    return redirect(url_for('reseller.dashboard'))

# ═══════════════════════════════════════════════════
# KEY ACTIONS (Revoke, Reset, Delete)
# ═══════════════════════════════════════════════════
@reseller_bp.route('/action/<action>/<int:lid>', methods=['POST'])
@login_required
def key_action(action, lid):
    if not str(current_user.id).startswith('res_'):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
    rid = int(str(current_user.id).replace('res_', ''))
    lic = License.query.get_or_404(lid)
    
    if lic.reseller_id != rid:
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

@reseller_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))
