import os
from datetime import timedelta
import pytz
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or 'salt-for-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///data/database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net;"
    }
    MFA_REQUIRED_FOR_ADMIN = True
    MFA_REQUIRED_FOR_TRANSFERS = True
    MFA_GRACE_PERIOD = 24
    FRAUD_THRESHOLD = 0.85
    MAX_DAILY_TRANSACTION_AMOUNT = 10000
    MAX_DAILY_TRANSACTION_COUNT = 20
    LOG_LEVEL = 'INFO'
    AUDIT_LOG_FILE = 'logs/audit.log'
    DISPLAY_TIMEZONE = 'Asia/Kolkata'
    TIMESTAMP_FORMAT = '%d-%m-%Y %H:%M:%S'
    TIMESTAMP_FORMAT_TIME_ONLY = '%H:%M:%S'
    TIMESTAMP_FORMAT_ISO = '%Y-%m-%d'
