"""
User Model - Represents a user account
"""

import hashlib
from datetime import datetime


class User:
    """User class representing a user account with authentication"""
    
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password_hash = self._hash_password(password)
        self.created_at = datetime.now()
        self.last_login = None
        self.is_active = True
        self.settings = {
            'alert_threshold': 5,  # Alert after 5 failed attempts
            'email_alerts': True,
            'two_factor_enabled': False
        }
    
    def _hash_password(self, password):
        """Hash password using SHA256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password):
        """Verify if provided password matches stored hash"""
        return self.password_hash == self._hash_password(password)
    
    def update_password(self, old_password, new_password):
        """Update user password after verification"""
        if not self.verify_password(old_password):
            raise ValueError("Current password is incorrect")
        
        if len(new_password) < 8:
            raise ValueError("New password must be at least 8 characters")
        
        self.password_hash = self._hash_password(new_password)
        return True
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.now()
    
    def lock_account(self):
        """Lock user account"""
        self.is_active = False
    
    def unlock_account(self):
        """Unlock user account"""
        self.is_active = True
    
    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active,
            'settings': self.settings
        }
