"""
Login Attempt Model - Tracks and manages login attempts
Uses data structures: Dictionary, List, Heap Queue for efficient operations
Uses algorithms: Binary Search, Pattern Matching, Sliding Window
"""

from datetime import datetime, timedelta
from collections import defaultdict, deque
import heapq
from typing import List, Dict, Tuple


class LoginAttempt:
    """Represents a single login attempt"""
    
    def __init__(self, username, ip_address, timestamp, status='pending'):
        self.username = username
        self.ip_address = ip_address
        self.timestamp = timestamp
        self.status = status  # 'success', 'failed', 'pending'
    
    def mark_success(self):
        """Mark attempt as successful"""
        self.status = 'success'
    
    def mark_failed(self):
        """Mark attempt as failed"""
        self.status = 'failed'
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'username': self.username,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status
        }


class LoginAttemptManager:
    """
    Manages login attempts with efficient data structures
    Data Structures Used:
    - defaultdict: For O(1) lookup of user attempts
    - deque: For maintaining sliding window of recent attempts
    - Dictionary: For IP-based statistics
    - Heap: For priority-based suspicious activity detection
    """
    
    def __init__(self, lockout_threshold=5, lockout_duration=30):
        self.attempts = defaultdict(list)  # username -> list of attempts
        self.ip_attempts = defaultdict(deque)  # IP -> deque of recent attempts
        self.user_lockouts = {}  # username -> lockout_until_time
        self.lockout_threshold = lockout_threshold  # Failed attempts threshold
        self.lockout_duration = lockout_duration  # Minutes
        self.ip_max_attempts = 10  # Per IP per hour
    
    def add_attempt(self, attempt: LoginAttempt) -> None:
        """Add a login attempt - O(1) operation"""
        self.attempts[attempt.username].append(attempt)
        
        # Maintain sliding window (last 100 attempts per IP)
        self.ip_attempts[attempt.ip_address].append(attempt)
        if len(self.ip_attempts[attempt.ip_address]) > 100:
            self.ip_attempts[attempt.ip_address].popleft()
    
    def mark_success(self, username: str, ip_address: str) -> None:
        """Mark last attempt as successful and remove lockout"""
        if username in self.attempts and self.attempts[username]:
            self.attempts[username][-1].mark_success()
        
        # Remove lockout if exists
        if username in self.user_lockouts:
            del self.user_lockouts[username]
    
    def mark_failed(self, username: str, ip_address: str) -> None:
        """Mark last attempt as failed and check for lockout"""
        if username in self.attempts and self.attempts[username]:
            self.attempts[username][-1].mark_failed()
        
        # Check if lockout threshold exceeded
        failed_count = self._count_recent_failed_attempts(username, minutes=30)
        if failed_count >= self.lockout_threshold:
            self._lockout_account(username)
    
    def is_account_locked(self, username: str) -> bool:
        """Check if account is currently locked - O(1) lookup"""
        if username not in self.user_lockouts:
            return False
        
        lockout_time = self.user_lockouts[username]
        if datetime.now() >= lockout_time:
            # Lockout expired
            del self.user_lockouts[username]
            return False
        
        return True
    
    def _lockout_account(self, username: str) -> None:
        """Lock account for specified duration"""
        lockout_until = datetime.now() + timedelta(minutes=self.lockout_duration)
        self.user_lockouts[username] = lockout_until
    
    def _count_recent_failed_attempts(self, username: str, minutes: int = 30) -> int:
        """
        Count failed attempts in last N minutes
        Algorithm: Linear scan with time filter - O(n) where n is recent attempts
        """
        if username not in self.attempts:
            return 0
        
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        count = 0
        
        # Scan from most recent backwards for efficiency
        for attempt in reversed(self.attempts[username][-100:]):
            if attempt.timestamp < cutoff_time:
                break
            if attempt.status == 'failed':
                count += 1
        
        return count
    
    def _count_recent_successful_attempts(self, username: str, minutes: int = 30) -> int:
        """Count successful attempts in last N minutes"""
        if username not in self.attempts:
            return 0
        
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        count = 0
        
        for attempt in reversed(self.attempts[username][-100:]):
            if attempt.timestamp < cutoff_time:
                break
            if attempt.status == 'success':
                count += 1
        
        return count
    
    def get_user_attempts(self, username: str, page: int = 1, limit: int = 10) -> List[LoginAttempt]:
        """
        Get paginated login attempts for user
        Algorithm: Slice operation - O(limit)
        """
        if username not in self.attempts:
            return []
        
        start = (page - 1) * limit
        end = start + limit
        all_attempts = self.attempts[username]
        
        # Return newest attempts first
        return list(reversed(all_attempts[start:end]))
    
    def get_user_attempt_count(self, username: str) -> int:
        """Get total attempt count for user - O(1)"""
        return len(self.attempts.get(username, []))
    
    def get_user_statistics(self, username: str) -> Dict:
        """
        Get comprehensive statistics for user
        Calculation: O(n) where n is number of recent attempts
        """
        if username not in self.attempts:
            return {
                'total_attempts': 0,
                'successful_attempts': 0,
                'failed_attempts': 0,
                'success_rate': 0,
                'recent_failed': 0,
                'is_locked': False,
                'unique_ips': 0
            }
        
        attempts = self.attempts[username]
        total = len(attempts)
        successful = sum(1 for a in attempts if a.status == 'success')
        failed = sum(1 for a in attempts if a.status == 'failed')
        
        # Get unique IPs - O(n)
        unique_ips = len(set(a.ip_address for a in attempts))
        
        # Calculate success rate
        success_rate = (successful / total * 100) if total > 0 else 0
        
        # Count recent failed attempts (last 30 minutes)
        recent_failed = self._count_recent_failed_attempts(username, minutes=30)
        
        return {
            'total_attempts': total,
            'successful_attempts': successful,
            'failed_attempts': failed,
            'success_rate': round(success_rate, 2),
            'recent_failed': recent_failed,
            'is_locked': self.is_account_locked(username),
            'unique_ips': unique_ips
        }
    
    def get_hourly_activity(self, username: str) -> Dict:
        """
        Get hourly activity breakdown for last 24 hours
        Algorithm: Time-based bucketing - O(n)
        """
        if username not in self.attempts:
            return {'hours': [], 'successful': [], 'failed': []}
        
        # Initialize 24 hours
        hours_data = {}
        now = datetime.now()
        for i in range(24):
            hour_key = (now - timedelta(hours=i)).strftime('%H:00')
            hours_data[hour_key] = {'successful': 0, 'failed': 0}
        
        # Count attempts per hour
        for attempt in self.attempts[username]:
            hour_key = attempt.timestamp.strftime('%H:00')
            if hour_key in hours_data:
                if attempt.status == 'success':
                    hours_data[hour_key]['successful'] += 1
                elif attempt.status == 'failed':
                    hours_data[hour_key]['failed'] += 1
        
        # Convert to lists
        hours = list(reversed(sorted(hours_data.keys())))
        successful = [hours_data[h]['successful'] for h in hours]
        failed = [hours_data[h]['failed'] for h in hours]
        
        return {
            'hours': hours,
            'successful': successful,
            'failed': failed
        }
    
    def get_ip_summary(self, username: str) -> Dict:
        """
        Get IP-based summary with success/failure counts
        Algorithm: Hash-based aggregation - O(n)
        """
        if username not in self.attempts:
            return []
        
        ip_stats = defaultdict(lambda: {'successful': 0, 'failed': 0, 'last_attempt': None})
        
        for attempt in self.attempts[username]:
            if attempt.status == 'success':
                ip_stats[attempt.ip_address]['successful'] += 1
            elif attempt.status == 'failed':
                ip_stats[attempt.ip_address]['failed'] += 1
            
            ip_stats[attempt.ip_address]['last_attempt'] = attempt.timestamp.isoformat()
        
        # Convert to sortable list and sort by latest attempt
        result = []
        for ip, stats in ip_stats.items():
            stats['ip'] = ip
            result.append(stats)
        
        # Sort by last attempt time (descending)
        result.sort(key=lambda x: x['last_attempt'], reverse=True)
        
        return result[:20]  # Return top 20 IPs
    
    def detect_brute_force_pattern(self, username: str, minutes: int = 10) -> bool:
        """
        Detect brute force pattern using sliding window
        Algorithm: Sliding window with fixed time interval - O(n)
        Returns: True if more than threshold attempts in window
        """
        if username not in self.attempts:
            return False
        
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        recent_attempts = [a for a in self.attempts[username] if a.timestamp > cutoff_time]
        
        # Brute force threshold: 5+ attempts in 10 minutes
        return len(recent_attempts) >= 5
    
    def get_suspicious_ips(self, username: str) -> List[Tuple[str, int]]:
        """
        Get IPs with unusual activity patterns
        Algorithm: Frequency analysis with threshold - O(n)
        """
        if username not in self.attempts:
            return []
        
        ip_failure_count = defaultdict(int)
        
        for attempt in self.attempts[username]:
            if attempt.status == 'failed':
                ip_failure_count[attempt.ip_address] += 1
        
        # Filter IPs with >2 failed attempts
        suspicious = [(ip, count) for ip, count in ip_failure_count.items() if count > 2]
        
        # Sort by failure count (descending)
        suspicious.sort(key=lambda x: x[1], reverse=True)
        
        return suspicious
