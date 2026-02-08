import numpy as np
from datetime import datetime, timedelta
import json
from collections import defaultdict
class FraudDetectionEngine:
    def __init__(self):
        self.transaction_history = defaultdict(list)
        self.user_profiles = {}
    def calculate_fraud_score(self, transaction, user_history):
        score = 0.0
        reasons = []
        avg_amount = np.mean([t['amount'] for t in user_history]) if user_history else 0
        if transaction['amount'] > avg_amount * 5:
            score += 0.3
            reasons.append("Amount significantly higher than average")
        if transaction['amount'] > 10000:
            score += 0.2
            reasons.append("Large transaction amount")
        recent_transactions = [
            t for t in user_history
            if datetime.utcnow() - t['timestamp'] < timedelta(hours=24)
        ]
        if len(recent_transactions) > 20:
            score += 0.3
            reasons.append("High transaction velocity")
        total_recent = sum(t['amount'] for t in recent_transactions)
        if total_recent > 50000:
            score += 0.3
            reasons.append("High daily transaction volume")
        transaction_hour = transaction['timestamp'].hour
        if transaction_hour < 6 or transaction_hour > 22:
            score += 0.1
            reasons.append("Unusual transaction time")
        if transaction.get('location') != user_history[-1].get('location') if user_history else None:
            score += 0.2
            reasons.append("Location change detected")
        if transaction.get('device_fingerprint') != user_history[-1].get('device_fingerprint') if user_history else None:
            score += 0.15
            reasons.append("Device change detected")
        return min(score, 1.0), reasons
    def train_user_profile(self, user_id, transactions):
        amounts = [t.amount for t in transactions]
        times = [t.created_at.hour for t in transactions]
        locations = [t.location for t in transactions if t.location]
        profile = {
            'avg_amount': np.mean(amounts) if amounts else 0,
            'std_amount': np.std(amounts) if amounts else 0,
            'common_hours': np.bincount(times).argmax() if times else 12,
            'common_location': max(set(locations), key=locations.count) if locations else None,
            'transaction_count': len(transactions)
        }
        self.user_profiles[user_id] = profile
        return profile
    def real_time_monitoring(self):
        return {
            'suspicious_activity': np.random.randint(0, 10),
            'fraud_prevented': np.random.randint(1000, 5000),
            'transactions_monitored': np.random.randint(10000, 50000),
            'false_positives': np.random.randint(0, 5),
            'threat_level': np.random.choice(['Low', 'Medium', 'High'])
        }
class BehavioralBiometrics:
    def __init__(self):
        self.user_patterns = {}
    def analyze_typing_pattern(self, username, keystroke_timings):
        if username not in self.user_patterns:
            self.user_patterns[username] = {
                'avg_speed': np.mean(keystroke_timings),
                'std_speed': np.std(keystroke_timings),
                'pattern': keystroke_timings
            }
            return 0.0
        baseline = self.user_patterns[username]
        current_avg = np.mean(keystroke_timings)
        deviation = abs(current_avg - baseline['avg_speed']) / baseline['std_speed'] if baseline['std_speed'] > 0 else 0
        return min(deviation, 1.0)
    def analyze_mouse_movements(self, movements):
        if len(movements) < 10:
            return 0.0
        speeds = []
        for i in range(1, len(movements)):
            dx = movements[i]['x'] - movements[i-1]['x']
            dy = movements[i]['y'] - movements[i-1]['y']
            dt = movements[i]['time'] - movements[i-1]['time']
            if dt > 0:
                speed = np.sqrt(dx**2 + dy**2) / dt
                speeds.append(speed)
        if not speeds:
            return 0.0
        std_dev = np.std(speeds)
        return min(std_dev / 100, 1.0)
