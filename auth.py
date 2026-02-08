import bcrypt
import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import datetime, timedelta
import hashlib
import secrets
from flask import current_app
class SecurityManager:
    def __init__(self):
        self.password_iterations = 260000
    def hash_password(self, password):
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    def verify_password(self, password, hashed):
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    def generate_mfa_secret(self):
        return pyotp.random_base32()
    def get_mfa_uri(self, username, secret):
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name="SecureBank"
        )
    def verify_totp(self, secret, token):
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
def generate_qr_code(self, uri):
    import qrcode
    import io
    import base64
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    ascii_qr = qr.get_matrix()
    ascii_str = ""
    for row in ascii_qr:
        ascii_str += "".join(["██" if cell else "  " for cell in row]) + "\n"
    return {
        'ascii': ascii_str,
        'uri': uri,
        'secret': uri.split('secret=')[1].split('&')[0] if 'secret=' in uri else ''
    }
    def generate_session_token(self):
        return secrets.token_urlsafe(32)
    def calculate_device_fingerprint(self, request):
        fingerprint_data = {
            'user_agent': request.user_agent.string,
            'accept_language': request.headers.get('Accept-Language', ''),
            'screen_resolution': request.headers.get('X-Screen-Resolution', ''),
            'timezone': request.headers.get('X-Timezone', ''),
        }
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()
    def check_password_strength(self, password):
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for c in password):
            return False, "Password must contain at least one special character"
        common_passwords = {'password', '123456', 'qwerty', 'letmein'}
        if password.lower() in common_passwords:
            return False, "Password is too common"
        return True, "Password is strong"
class RateLimiter:
    def __init__(self):
        self.attempts = {}
    def check_rate_limit(self, ip_address, endpoint):
        key = f"{ip_address}:{endpoint}"
        now = datetime.utcnow()
        if key not in self.attempts:
            self.attempts[key] = []
        self.attempts[key] = [
            attempt for attempt in self.attempts[key]
            if now - attempt < timedelta(hours=1)
        ]
        if len(self.attempts[key]) >= 10:
            return False
        self.attempts[key].append(now)
        return True