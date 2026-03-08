"""
Login System Classes - Object-Oriented Design
Includes data structures and algorithms for monitoring and threat detection
"""

from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import uuid
import re


class ThreatLevel(Enum):
    """Threat level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class User:
    """User class representing a system user"""
    username: str
    email: str
    password_hash: str = field(default='')
    user_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.now)
    is_locked: bool = False
    two_factor_enabled: bool = False
    login_notifications_enabled: bool = True
    
    def __init__(self, username: str, email: str, password: str):
        self.username = username
        self.email = email
        self.password_hash = self._hash_password(password)
        self.user_id = str(uuid.uuid4())
        self.created_at = datetime.now()
        self.is_locked = False
        self.two_factor_enabled = False
        self.login_notifications_enabled = True
    
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password: str) -> bool:
        """Verify password matches hash"""
        return self.password_hash == self._hash_password(password)
    
    def __repr__(self) -> str:
        return f"User({self.username}, {self.email})"


@dataclass
class LoginAttempt:
    """LoginAttempt class representing a single login attempt"""
    username: str
    ip_address: str
    attempt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = False
    threat_level: str = "low"
    user_agent: str = ""
    location: Optional[str] = None
    
    def __init__(self, username: str, ip_address: str):
        self.username = username
        self.ip_address = ip_address
        self.attempt_id = str(uuid.uuid4())
        self.timestamp = datetime.now()
        self.success = False
        self.threat_level = "low"
        self.user_agent = ""
        self.location = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'attempt_id': self.attempt_id,
            'username': self.username,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat(),
            'success': self.success,
            'threat_level': self.threat_level,
            'user_agent': self.user_agent,
            'location': self.location
        }
    
    def __repr__(self) -> str:
        status = "✓ Success" if self.success else "✗ Failed"
        return f"LoginAttempt({self.username}@{self.ip_address} - {status})"


class LoginAttemptMonitor:
    """Monitor class for tracking login attempts - uses Queue data structure"""
    
    def __init__(self, max_attempts: int = 10000):
        # Use deque for efficient FIFO operations
        self._attempt_queue: deque = deque(maxlen=max_attempts)
        self._attempts_by_user: defaultdict = defaultdict(list)
        self._attempts_by_ip: defaultdict = defaultdict(list)
    
    def add_attempt(self, attempt: LoginAttempt) -> None:
        """Add login attempt to monitoring queue"""
        self._attempt_queue.append(attempt)
        self._attempts_by_user[attempt.username].append(attempt)
        self._attempts_by_ip[attempt.ip_address].append(attempt)
    
    def get_recent_attempts(self, minutes: int = 60) -> List[LoginAttempt]:
        """Get attempts from last N minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        return [attempt for attempt in self._attempt_queue 
                if attempt.timestamp > cutoff_time]
    
    def get_failed_attempts_count(self, username: str, minutes: int = 30) -> int:
        """Count failed attempts for user in last N minutes - O(n) algorithm"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        count = 0
        for attempt in self._attempts_by_user[username]:
            if not attempt.success and attempt.timestamp > cutoff_time:
                count += 1
        return count
    
    def get_ip_login_count(self, ip_address: str, minutes: int = 60) -> int:
        """Get login attempt count from IP address in last N minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        count = 0
        for attempt in self._attempts_by_ip[ip_address]:
            if attempt.timestamp > cutoff_time:
                count += 1
        return count
    
    def detect_unusual_activity(self, username: str) -> bool:
        """Detect unusual activity patterns using simple algorithm"""
        recent = self._attempts_by_user[username][-10:]  # Last 10 attempts
        
        if len(recent) < 3:
            return False
        
        # Check for rapid successive attempts
        for i in range(len(recent) - 1):
            time_diff = (recent[i+1].timestamp - recent[i].timestamp).total_seconds()
            if time_diff < 5:  # Less than 5 seconds between attempts
                return True
        
        # Check for multiple IPs in short time
        ips = set(attempt.ip_address for attempt in recent)
        if len(ips) > 3 and len(recent) == 10:
            return True
        
        return False
    
    def get_threats_for_user(self, username: str) -> List[Dict]:
        """Get active threats for user"""
        threats = []
        recent = self._attempts_by_user[username][-100:]
        
        # Check for brute force attempts
        failed_count = sum(1 for attempt in recent if not attempt.success)
        if failed_count > 5:
            threats.append({
                'type': 'Potential Brute Force',
                'severity': 'high',
                'count': failed_count
            })
        
        # Check for multiple IPs
        ips = set(attempt.ip_address for attempt in recent)
        if len(ips) > 5:
            threats.append({
                'type': 'Multiple IPs',
                'severity': 'medium',
                'count': len(ips)
            })
        
        return threats
    
    def __repr__(self) -> str:
        return f"LoginAttemptMonitor(Total: {len(self._attempt_queue)}, Users: {len(self._attempts_by_user)})"


class ThreatDetector:
    """Threat detection using machine learning-like heuristics"""
    
    def __init__(self):
        self.threat_weights = {
            'failed_login': 10,
            'rapid_attempts': 15,
            'multiple_ips': 20,
            'unusual_time': 5,
            'new_ip': 15,
            'geolocation_change': 25
        }
    
    def analyze_login_attempt(self, username: str, ip_address: str, 
                            history: List[LoginAttempt]) -> str:
        """Analyze login attempt and return threat level"""
        threat_score = 0
        
        # Calculate threat score
        if not history:
            return "low"
        
        # Check for previous failed attempts from same IP
        recent_attempts = [a for a in history 
                          if (datetime.now() - a.timestamp).total_seconds() < 3600]
        failed_count = sum(1 for a in recent_attempts if not a.success)
        
        if failed_count > 3:
            threat_score += self.threat_weights['failed_login']
        
        # Check for rapid attempts (brute force detection)
        if len(recent_attempts) > 5:
            time_diffs = []
            for i in range(len(recent_attempts) - 1):
                diff = (recent_attempts[i+1].timestamp - 
                       recent_attempts[i].timestamp).total_seconds()
                time_diffs.append(diff)
            
            avg_time_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 0
            if avg_time_diff < 10:
                threat_score += self.threat_weights['rapid_attempts']
        
        # Check if IP is new
        known_ips = set(a.ip_address for a in history)
        if ip_address not in known_ips:
            threat_score += self.threat_weights['new_ip']
        
        # Return threat level based on score
        if threat_score >= 50:
            return "critical"
        elif threat_score >= 35:
            return "high"
        elif threat_score >= 20:
            return "medium"
        else:
            return "low"
    
    def detailed_analysis(self, username: str, history: List[LoginAttempt]) -> Dict:
        """Provide detailed threat analysis"""
        if not history:
            return {
                'total_attempts': 0,
                'success_rate': 0,
                'unique_ips': 0,
                'risk_factors': []
            }
        
        successful = sum(1 for a in history if a.success)
        total = len(history)
        success_rate = (successful / total * 100) if total > 0 else 0
        
        unique_ips = len(set(a.ip_address for a in history))
        
        risk_factors = []
        
        # Check for low success rate
        if success_rate < 30:
            risk_factors.append('Low success rate - possible brute force attacks')
        
        # Check for many unique IPs
        if unique_ips > 5:
            risk_factors.append(f'Multiple login IPs detected ({unique_ips})')
        
        # Check for failed attempts recently
        recent_attempts = [a for a in history[-10:] if not a.success]
        if len(recent_attempts) > 3:
            risk_factors.append('Multiple recent failed login attempts')
        
        return {
            'total_attempts': total,
            'successful_attempts': successful,
            'failed_attempts': total - successful,
            'success_rate': round(success_rate, 2),
            'unique_ips': unique_ips,
            'risk_factors': risk_factors,
            'analysis_date': datetime.now().isoformat()
        }


class LoginAnalytics:
    """Analytics engine for generating statistics - uses algorithms for analysis"""
    
    def generate_statistics(self, attempts: List[LoginAttempt]) -> Dict:
        """Generate statistical analysis of login attempts"""
        if not attempts:
            return self._empty_stats()
        
        total = len(attempts)
        successful = sum(1 for a in attempts if a.success)
        failed = total - successful
        
        # Calculate success rate
        success_rate = (successful / total * 100) if total > 0 else 0
        
        # Get unique IPs
        unique_ips = len(set(a.ip_address for a in attempts))
        
        # Calculate average time between attempts
        if len(attempts) > 1:
            time_diffs = []
            for i in range(len(attempts) - 1):
                diff = (attempts[i+1].timestamp - attempts[i].timestamp).total_seconds()
                time_diffs.append(diff)
            avg_time_between = sum(time_diffs) / len(time_diffs)
        else:
            avg_time_between = 0
        
        # Peak login times - histogram algorithm
        hour_counts = defaultdict(int)
        for attempt in attempts:
            hour = attempt.timestamp.hour
            hour_counts[hour] += 1
        
        peak_hour = max(hour_counts.items(), key=lambda x: x[1])[0] if hour_counts else 0
        
        # Threat level distribution
        threat_distribution = defaultdict(int)
        for attempt in attempts:
            threat_distribution[attempt.threat_level] += 1
        
        return {
            'total_attempts': total,
            'successful_attempts': successful,
            'failed_attempts': failed,
            'success_rate': round(success_rate, 2),
            'unique_ips': unique_ips,
            'avg_time_between_attempts': round(avg_time_between, 2),
            'peak_login_hour': peak_hour,
            'threat_distribution': dict(threat_distribution),
            'last_login': attempts[-1].timestamp.isoformat() if attempts else None
        }
    
    def _empty_stats(self) -> Dict:
        """Return empty statistics object"""
        return {
            'total_attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'success_rate': 0,
            'unique_ips': 0,
            'avg_time_between_attempts': 0,
            'peak_login_hour': 0,
            'threat_distribution': {},
            'last_login': None
        }


class NotificationManager:
    """Notification system for alerting users"""
    
    def __init__(self):
        self._notifications: deque = deque(maxlen=1000)
    
    def send_notification(self, email: str, message: str) -> bool:
        """Send notification to user (simulated email)"""
        notification = {
            'email': email,
            'message': message,
            'timestamp': datetime.now(),
            'status': 'sent'
        }
        self._notifications.append(notification)
        return True
    
    def get_notifications(self) -> List[Dict]:
        """Get all notifications"""
        return list(self._notifications)


class RateLimiter:
    """Rate limiting using sliding window algorithm"""
    
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: defaultdict = defaultdict(deque)
    
    def is_rate_limited(self, key: str) -> bool:
        """Check if key is rate limited using sliding window"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        # Remove old attempts outside window
        while self._attempts[key] and self._attempts[key][0] < cutoff:
            self._attempts[key].popleft()
        
        # Check if over limit
        return len(self._attempts[key]) >= self.max_attempts
    
    def record_attempt(self, key: str) -> None:
        """Record an attempt"""
        self._attempts[key].append(datetime.now())
    
    def get_remaining_attempts(self, key: str) -> int:
        """Get remaining attempts for key"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        # Remove old attempts
        while self._attempts[key] and self._attempts[key][0] < cutoff:
            self._attempts[key].popleft()
        
        return max(0, self.max_attempts - len(self._attempts[key]))
