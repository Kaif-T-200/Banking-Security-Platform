from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import json
import bleach
import hashlib
import pyotp
from timezone_utils import TimezoneConverter, format_ist, format_ist_time_ago
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///banking.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.jinja_env.filters['ist'] = format_ist
app.jinja_env.filters['ist_time_ago'] = format_ist_time_ago
app.jinja_env.filters['format_ist'] = format_ist
app.jinja_env.filters['format_ist_time_ago'] = format_ist_time_ago
app.jinja_env.globals['TimezoneConverter'] = TimezoneConverter
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='customer')
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32))
    login_attempts = db.Column(db.Integer, default=0)
    account_locked = db.Column(db.Boolean, default=False)
    lockout_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    accounts = db.relationship('Account', backref='owner', lazy=True)
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    security_logs = db.relationship('SecurityLog', backref='user', lazy=True)
class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    balance = db.Column(db.Float, default=0.00)
    account_type = db.Column(db.String(20), default='checking')
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(36), unique=True, nullable=False)
    from_account = db.Column(db.String(20), nullable=False)
    to_account = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(20))
    status = db.Column(db.String(20), default='pending')
    fraud_score = db.Column(db.Float, default=0.0)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    event_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), default='info')
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
def audit_log(event_type, severity, description, user_id=None):
    log = SecurityLog(
        user_id=user_id,
        event_type=event_type,
        severity=severity,
        description=description,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
def check_password_strength(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain uppercase letters"
    if not any(c.islower() for c in password):
        return False, "Password must contain lowercase letters"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain numbers"
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for c in password):
        return False, "Password must contain special characters"
    return True, "Password is strong"
def calculate_fraud_score(transaction, user_history):
    score = 0.0
    if transaction['amount'] > 10000:
        score += 0.3
    hour = datetime.utcnow().hour
    if hour < 6:
        score += 0.2
    recent_tx = len([t for t in user_history if
                    (datetime.utcnow() - t.created_at).seconds < 3600])
    if recent_tx > 10:
        score += 0.3
    return min(score, 1.0)
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = bleach.clean(data.get('username', ''))
        password = data.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and not user.account_locked:
            if check_password_hash(user.password_hash, password):
                user.login_attempts = 0
                db.session.commit()
                audit_log('login_success', 'info',
                         f'User {username} logged in successfully', user.id)
                login_user(user)
                if user.mfa_enabled:
                    return jsonify({'mfa_required': True})
                return jsonify({'success': True, 'redirect': '/dashboard'})
            else:
                user.login_attempts += 1
                if user.login_attempts >= 5:
                    user.account_locked = True
                    user.lockout_until = datetime.utcnow() + timedelta(minutes=15)
                    audit_log('account_locked', 'critical',
                             'Account locked due to multiple failed attempts', user.id)
                db.session.commit()
                audit_log('login_failed', 'warning',
                         f'Failed login attempt for {username}', user.id)
        return jsonify({'error': 'Invalid credentials'}), 401
    return render_template('login.html')
@app.route('/verify-mfa', methods=['POST'])
@login_required
def verify_mfa():
    data = request.get_json()
    token = data.get('token', '')
    if not current_user.mfa_secret:
        return jsonify({'error': 'MFA not set up'}), 400
    totp = pyotp.TOTP(current_user.mfa_secret)
    if totp.verify(token, valid_window=1):
        session['mfa_verified'] = True
        audit_log('mfa_success', 'info', 'MFA verification successful', current_user.id)
        return jsonify({'success': True})
    audit_log('mfa_failed', 'warning', 'MFA verification failed', current_user.id)
    return jsonify({'error': 'Invalid token'}), 401
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.mfa_enabled and not session.get('mfa_verified'):
        return redirect(url_for('mfa_prompt'))
    accounts = Account.query.filter_by(user_id=current_user.id).all()
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(
        Transaction.created_at.desc()).limit(10).all()
    return render_template('dashboard.html',
                         accounts=accounts,
                         transactions=transactions)
@app.route('/mfa-prompt')
@login_required
def mfa_prompt():
    if not current_user.mfa_enabled:
        return redirect(url_for('dashboard'))
    return render_template('mfa_prompt.html')
@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    if current_user.mfa_enabled and not session.get('mfa_verified'):
        return jsonify({'error': 'MFA verification required'}), 403
    data = request.get_json()
    try:
        amount = float(bleach.clean(str(data.get('amount', '0'))))
        to_account = bleach.clean(data.get('to_account', ''))
        description = bleach.clean(data.get('description', ''))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid input data'}), 400
    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400
    from_account = Account.query.filter_by(
        user_id=current_user.id,
        account_type='checking'
    ).first()
    if not from_account:
        return jsonify({'error': 'No checking account found'}), 404
    if from_account.balance < amount:
        return jsonify({'error': 'Insufficient funds'}), 400
    user_history = Transaction.query.filter_by(user_id=current_user.id).all()
    fraud_score = calculate_fraud_score({'amount': amount}, user_history)
    transaction = Transaction(
        transaction_id=secrets.token_urlsafe(16),
        from_account=from_account.account_number,
        to_account=to_account,
        amount=amount,
        transaction_type='transfer',
        status='pending' if fraud_score < 0.8 else 'flagged',
        fraud_score=fraud_score,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        user_id=current_user.id
    )
    from_account.balance -= amount
    db.session.add(transaction)
    db.session.commit()
    audit_log('transfer_initiated', 'info',
             f'Transfer of ${amount} from {from_account.account_number} to {to_account}',
             current_user.id)
    return jsonify({
        'success': True,
        'transaction_id': transaction.transaction_id,
        'fraud_score': fraud_score,
        'new_balance': from_account.balance
    })
@app.route('/security-dashboard')
@login_required
def security_dashboard():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    logs = SecurityLog.query.order_by(SecurityLog.created_at.desc()).limit(50).all()
    flagged_tx = Transaction.query.filter(Transaction.fraud_score > 0.7).count()
    locked_accounts = User.query.filter_by(account_locked=True).count()
    return render_template('security_dashboard.html',
                         logs=logs,
                         flagged_transactions=flagged_tx,
                         locked_accounts=locked_accounts)
@app.route('/api/security-metrics')
@login_required
def security_metrics():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    import random
    return jsonify({
        'active_sessions': random.randint(10, 100),
        'failed_logins': SecurityLog.query.filter_by(
            event_type='login_failed'
        ).filter(
            SecurityLog.created_at > datetime.utcnow() - timedelta(hours=24)
        ).count(),
        'fraud_prevented': random.randint(1000, 10000),
        'threat_level': random.choice(['Low', 'Medium', 'High']),
        'system_health': random.randint(95, 100)
    })
@app.route('/logout')
@login_required
def logout():
    audit_log('logout', 'info', 'User logged out', current_user.id)
    logout_user()
    session.clear()
    return redirect(url_for('index'))
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@securebank.com',
            password_hash=generate_password_hash('Admin@Secure123!'),
            role='admin',
            mfa_enabled=True,
            mfa_secret=pyotp.random_base32()
        )
        db.session.add(admin)
        db.session.commit()
        account = Account(
            account_number='1000000001',
            user_id=admin.id,
            balance=10000.00
        )
        db.session.add(account)
        db.session.commit()
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
