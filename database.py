"""
Database Module - File-based persistence layer
"""

import json
import os
from datetime import datetime
from typing import List, Optional, Dict
from login_system import User, LoginAttempt
import threading


class Database:
    """Database class for managing data persistence"""
    
    def __init__(self, data_dir: str = 'data'):
        self.data_dir = data_dir
        self.users_file = os.path.join(data_dir, 'users.json')
        self.attempts_file = os.path.join(data_dir, 'login_attempts.json')
        self._lock = threading.Lock()
        
        # Create data directory if not exists
        os.makedirs(data_dir, exist_ok=True)
        
        # Initialize files if not exist
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                json.dump({}, f)
        
        if not os.path.exists(self.attempts_file):
            with open(self.attempts_file, 'w') as f:
                json.dump([], f)
    
    def save_user(self, user: User) -> bool:
        """Save user to database"""
        try:
            with self._lock:
                users = self._read_users()
                users[user.user_id] = {
                    'user_id': user.user_id,
                    'username': user.username,
                    'email': user.email,
                    'password_hash': user.password_hash,
                    'created_at': user.created_at.isoformat(),
                    'is_locked': user.is_locked,
                    'two_factor_enabled': user.two_factor_enabled,
                    'login_notifications_enabled': user.login_notifications_enabled
                }
                self._write_users(users)
                return True
        except Exception as e:
            print(f"Error saving user: {e}")
            return False
    
    def get_user(self, username: str) -> Optional[User]:
        """Get user by username"""
        try:
            users = self._read_users()
            for user_data in users.values():
                if user_data['username'] == username:
                    user = User.__new__(User)
                    user.user_id = user_data['user_id']
                    user.username = user_data['username']
                    user.email = user_data['email']
                    user.password_hash = user_data['password_hash']
                    user.created_at = datetime.fromisoformat(user_data['created_at'])
                    user.is_locked = user_data.get('is_locked', False)
                    user.two_factor_enabled = user_data.get('two_factor_enabled', False)
                    user.login_notifications_enabled = user_data.get('login_notifications_enabled', True)
                    return user
            return None
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def update_user(self, user: User) -> bool:
        """Update user in database"""
        try:
            with self._lock:
                users = self._read_users()
                users[user.user_id] = {
                    'user_id': user.user_id,
                    'username': user.username,
                    'email': user.email,
                    'password_hash': user.password_hash,
                    'created_at': user.created_at.isoformat(),
                    'is_locked': user.is_locked,
                    'two_factor_enabled': user.two_factor_enabled,
                    'login_notifications_enabled': user.login_notifications_enabled
                }
                self._write_users(users)
                return True
        except Exception as e:
            print(f"Error updating user: {e}")
            return False
    
    def lock_user_account(self, username: str) -> bool:
        """Lock user account"""
        user = self.get_user(username)
        if user:
            user.is_locked = True
            return self.update_user(user)
        return False
    
    def save_login_attempt(self, attempt: LoginAttempt) -> bool:
        """Save login attempt to database"""
        try:
            with self._lock:
                attempts = self._read_attempts()
                attempts.append(attempt.to_dict())
                self._write_attempts(attempts)
                return True
        except Exception as e:
            print(f"Error saving login attempt: {e}")
            return False
    
    def get_login_history(self, username: str, limit: int = 100, 
                         offset: int = 0) -> List[LoginAttempt]:
        """Get login history for user with pagination"""
        try:
            attempts = self._read_attempts()
            user_attempts = [a for a in attempts if a['username'] == username]
            
            # Sort by timestamp descending
            user_attempts.sort(key=lambda x: x['timestamp'], reverse=True)
            
            # Apply pagination
            paginated = user_attempts[offset:offset + limit]
            
            result = []
            for attempt_data in paginated:
                attempt = LoginAttempt.__new__(LoginAttempt)
                attempt.attempt_id = attempt_data['attempt_id']
                attempt.username = attempt_data['username']
                attempt.ip_address = attempt_data['ip_address']
                attempt.timestamp = datetime.fromisoformat(attempt_data['timestamp'])
                attempt.success = attempt_data['success']
                attempt.threat_level = attempt_data.get('threat_level', 'low')
                attempt.user_agent = attempt_data.get('user_agent', '')
                attempt.location = attempt_data.get('location')
                result.append(attempt)
            
            return result
        except Exception as e:
            print(f"Error getting login history: {e}")
            return []
    
    def _read_users(self) -> Dict:
        """Read users from file"""
        with open(self.users_file, 'r') as f:
            return json.load(f)
    
    def _write_users(self, users: Dict) -> None:
        """Write users to file"""
        with open(self.users_file, 'w') as f:
            json.dump(users, f, indent=2)
    
    def _read_attempts(self) -> List[Dict]:
        """Read login attempts from file"""
        with open(self.attempts_file, 'r') as f:
            return json.load(f)
    
    def _write_attempts(self, attempts: List[Dict]) -> None:
        """Write login attempts to file"""
        with open(self.attempts_file, 'w') as f:
            json.dump(attempts, f, indent=2)
    
    def get_statistics(self, username: str) -> Dict:
        """Get statistics for user"""
        attempts = self.get_login_history(username, limit=1000)
        
        total = len(attempts)
        successful = sum(1 for a in attempts if a.success)
        failed = total - successful
        
        return {
            'total_attempts': total,
            'successful_attempts': successful,
            'failed_attempts': failed,
            'success_rate': (successful / total * 100) if total > 0 else 0
        }
