from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
import uuid
import json
db = SQLAlchemy()
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='customer')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32))
    last_login = db.Column(db.DateTime)
    login_attempts = db.Column(db.Integer, default=0)
    account_locked = db.Column(db.Boolean, default=False)
    lockout_until = db.Column(db.DateTime)
    typical_login_time = db.Column(db.String(10))
    typical_login_location = db.Column(db.String(100))
    accounts = db.relationship('Account', backref='owner', lazy=True)
    sessions = db.relationship('UserSession', backref='user', lazy=True)
    security_logs = db.relationship('SecurityLog', backref='user', lazy=True)
    def __repr__(self):
        return f'<User {self.username}>'
class Account(db.Model):
    __tablename__ = 'accounts'
    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    account_type = db.Column(db.String(20), default='checking')
    balance = db.Column(db.Numeric(15, 2), default=0.00)
    currency = db.Column(db.String(3), default='USD')
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    daily_withdrawal_limit = db.Column(db.Numeric(15, 2), default=1000.00)
    daily_transfer_limit = db.Column(db.Numeric(15, 2), default=5000.00)
    last_transaction_at = db.Column(db.DateTime)
    transactions = db.relationship('Transaction', backref='account', lazy=True)
    def __repr__(self):
        return f'<Account {self.account_number}>'
class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    from_account = db.Column(db.String(20), nullable=False)
    to_account = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Numeric(15, 2), nullable=False)
    currency = db.Column(db.String(3), default='USD')
    transaction_type = db.Column(db.String(20))
    description = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')
    fraud_score = db.Column(db.Float, default=0.0)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    location = db.Column(db.String(100))
    device_fingerprint = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'))
    security_reviews = db.relationship('SecurityReview', backref='transaction', lazy=True)
    def to_dict(self):
        return {
            'id': self.transaction_id,
            'from': self.from_account,
            'to': self.to_account,
            'amount': float(self.amount),
            'type': self.transaction_type,
            'status': self.status,
            'fraud_score': self.fraud_score,
            'timestamp': self.created_at.isoformat()
        }
class UserSession(db.Model):
    __tablename__ = 'user_sessions'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    location = db.Column(db.String(100))
    device_fingerprint = db.Column(db.String(64))
    login_successful = db.Column(db.Boolean, default=True)
    risk_score = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    def is_expired(self):
        return datetime.utcnow() > self.expires_at
    def update_activity(self):
        self.last_activity = datetime.utcnow()
        db.session.commit()
class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    event_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), default='info')
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    metadata = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def set_metadata(self, data):
        self.metadata = json.dumps(data)
    def get_metadata(self):
        return json.loads(self.metadata) if self.metadata else {}
class SecurityReview(db.Model):
    __tablename__ = 'security_reviews'
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey('transactions.id'))
    reviewed_by = db.Column(db.String(80))
    decision = db.Column(db.String(20))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Account(db.Model):
    __tablename__ = 'accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    account_type = db.Column(db.String(20), default='checking')
    balance = db.Column(db.Numeric(15, 2), default=0.00)
    currency = db.Column(db.String(3), default='USD')
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Security
    daily_withdrawal_limit = db.Column(db.Numeric(15, 2), default=1000.00)
    daily_transfer_limit = db.Column(db.Numeric(15, 2), default=5000.00)
    last_transaction_at = db.Column(db.DateTime)
    
    # Relationships
    transactions = db.relationship('Transaction', backref='account', lazy=True)
    
    def __repr__(self):
        return f'<Account {self.account_number}>'

class Transaction(db.Model):
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    from_account = db.Column(db.String(20), nullable=False)
    to_account = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Numeric(15, 2), nullable=False)
    currency = db.Column(db.String(3), default='USD')
    transaction_type = db.Column(db.String(20))  # deposit, withdrawal, transfer
    description = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed, flagged
    fraud_score = db.Column(db.Float, default=0.0)
    
    # Enhanced Security
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    location = db.Column(db.String(100))
    device_fingerprint = db.Column(db.String(64))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'))
    security_reviews = db.relationship('SecurityReview', backref='transaction', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.transaction_id,
            'from': self.from_account,
            'to': self.to_account,
            'amount': float(self.amount),
            'type': self.transaction_type,
            'status': self.status,
            'fraud_score': self.fraud_score,
            'timestamp': self.created_at.isoformat()
        }

class UserSession(db.Model):
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    location = db.Column(db.String(100))
    device_fingerprint = db.Column(db.String(64))
    
    # Security Metrics
    login_successful = db.Column(db.Boolean, default=True)
    risk_score = db.Column(db.Float, default=0.0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    def is_expired(self):
        return datetime.utcnow() > self.expires_at
    
    def update_activity(self):
        self.last_activity = datetime.utcnow()
        db.session.commit()

class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    event_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), default='info')  # info, warning, critical
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    
    # Metadata
    metadata = db.Column(db.Text)  # JSON encoded additional data
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_metadata(self, data):
        self.metadata = json.dumps(data)
    
    def get_metadata(self):
        return json.loads(self.metadata) if self.metadata else {}

class SecurityReview(db.Model):
    __tablename__ = 'security_reviews'
    
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey('transactions.id'))
    reviewed_by = db.Column(db.String(80))
    decision = db.Column(db.String(20))  # approved, rejected, flagged
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)