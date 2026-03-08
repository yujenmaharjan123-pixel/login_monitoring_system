"""
Unit Tests - Comprehensive testing for Login Attempt Monitoring System
"""

import unittest
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.models.user import User
from app.models.login_attempt import LoginAttempt, LoginAttemptManager
from app.models.security_analyzer import SecurityAnalyzer
from app.utils.validators import Validator
from app.utils.logger import SystemLogger


class TestUser(unittest.TestCase):
    """Test cases for User model"""
    
    def setUp(self):
        """Create test user"""
        self.user = User('testuser', 'test@example.com', 'TestPass123')
    
    def test_user_creation(self):
        """Test user is created correctly"""
        self.assertEqual(self.user.username, 'testuser')
        self.assertEqual(self.user.email, 'test@example.com')
        self.assertTrue(self.user.is_active)
    
    def test_password_hashing(self):
        """Test password is hashed, not stored plaintext"""
        self.assertNotEqual(self.user.password_hash, 'TestPass123')
    
    def test_password_verification(self):
        """Test password verification"""
        self.assertTrue(self.user.verify_password('TestPass123'))
        self.assertFalse(self.user.verify_password('WrongPassword'))
    
    def test_password_update(self):
        """Test password update functionality"""
        self.user.update_password('TestPass123', 'NewPass456')
        self.assertTrue(self.user.verify_password('NewPass456'))
        self.assertFalse(self.user.verify_password('TestPass123'))
    
    def test_password_update_fails_with_wrong_old_password(self):
        """Test password update fails with incorrect old password"""
        with self.assertRaises(ValueError):
            self.user.update_password('WrongPass', 'NewPass456')
    
    def test_account_locking(self):
        """Test account locking/unlocking"""
        self.user.lock_account()
        self.assertFalse(self.user.is_active)
        
        self.user.unlock_account()
        self.assertTrue(self.user.is_active)
    
    def test_user_to_dict(self):
        """Test user conversion to dictionary"""
        user_dict = self.user.to_dict()
        self.assertEqual(user_dict['username'], 'testuser')
        self.assertEqual(user_dict['email'], 'test@example.com')
        self.assertTrue(user_dict['is_active'])


class TestLoginAttempt(unittest.TestCase):
    """Test cases for LoginAttempt model"""
    
    def setUp(self):
        """Create test attempt"""
        self.attempt = LoginAttempt('testuser', '192.168.1.1', datetime.now())
    
    def test_attempt_creation(self):
        """Test attempt is created with correct data"""
        self.assertEqual(self.attempt.username, 'testuser')
        self.assertEqual(self.attempt.ip_address, '192.168.1.1')
        self.assertEqual(self.attempt.status, 'pending')
    
    def test_mark_success(self):
        """Test marking attempt as success"""
        self.attempt.mark_success()
        self.assertEqual(self.attempt.status, 'success')
    
    def test_mark_failed(self):
        """Test marking attempt as failed"""
        self.attempt.mark_failed()
        self.assertEqual(self.attempt.status, 'failed')
    
    def test_attempt_to_dict(self):
        """Test attempt conversion to dictionary"""
        self.attempt.mark_success()
        attempt_dict = self.attempt.to_dict()
        self.assertEqual(attempt_dict['status'], 'success')
        self.assertEqual(attempt_dict['username'], 'testuser')


class TestLoginAttemptManager(unittest.TestCase):
    """Test cases for LoginAttemptManager"""
    
    def setUp(self):
        """Create manager and test data"""
        self.manager = LoginAttemptManager()
    
    def test_add_attempt(self):
        """Test adding attempts"""
        attempt = LoginAttempt('user1', '192.168.1.1', datetime.now())
        self.manager.add_attempt(attempt)
        
        self.assertEqual(self.manager.get_user_attempt_count('user1'), 1)
    
    def test_mark_success(self):
        """Test marking attempts as successful"""
        attempt = LoginAttempt('user1', '192.168.1.1', datetime.now())
        self.manager.add_attempt(attempt)
        self.manager.mark_success('user1', '192.168.1.1')
        
        attempts = self.manager.get_user_attempts('user1')
        self.assertEqual(attempts[0].status, 'success')
    
    def test_mark_failed_single(self):
        """Test marking single failed attempt"""
        attempt = LoginAttempt('user1', '192.168.1.1', datetime.now())
        self.manager.add_attempt(attempt)
        self.manager.mark_failed('user1', '192.168.1.1')
        
        attempts = self.manager.get_user_attempts('user1')
        self.assertEqual(attempts[0].status, 'failed')
    
    def test_account_lockout(self):
        """Test account lockout after threshold"""
        # Add 5 failed attempts (lockout threshold)
        for i in range(5):
            attempt = LoginAttempt('user1', '192.168.1.1', datetime.now())
            self.manager.add_attempt(attempt)
            self.manager.mark_failed('user1', '192.168.1.1')
        
        # Account should be locked
        self.assertTrue(self.manager.is_account_locked('user1'))
    
    def test_lockout_expiration(self):
        """Test lockout expires after time"""
        # Lock account
        for i in range(5):
            attempt = LoginAttempt('user1', '192.168.1.1', datetime.now())
            self.manager.add_attempt(attempt)
            self.manager.mark_failed('user1', '192.168.1.1')
        
        # Manually set lockout to past time
        self.manager.user_lockouts['user1'] = datetime.now() - timedelta(minutes=1)
        
        # Should not be locked
        self.assertFalse(self.manager.is_account_locked('user1'))
    
    def test_get_statistics(self):
        """Test statistics calculation"""
        # Add successful attempts
        for i in range(3):
            attempt = LoginAttempt('user1', '192.168.1.1', datetime.now())
            self.manager.add_attempt(attempt)
            self.manager.mark_success('user1', '192.168.1.1')
        
        # Add failed attempts
        for i in range(2):
            attempt = LoginAttempt('user1', '192.168.1.1', datetime.now())
            self.manager.add_attempt(attempt)
            self.manager.mark_failed('user1', '192.168.1.1')
        
        stats = self.manager.get_user_statistics('user1')
        
        self.assertEqual(stats['total_attempts'], 5)
        self.assertEqual(stats['successful_attempts'], 3)
        self.assertEqual(stats['failed_attempts'], 2)
        self.assertEqual(stats['success_rate'], 60.0)
    
    def test_brute_force_detection(self):
        """Test brute force pattern detection"""
        # Add 5 attempts within 10 minutes
        now = datetime.now()
        for i in range(5):
            attempt = LoginAttempt('user1', '192.168.1.1', now - timedelta(minutes=i))
            self.manager.add_attempt(attempt)
        
        # Should detect brute force
        self.assertTrue(self.manager.detect_brute_force_pattern('user1'))
    
    def test_get_suspicious_ips(self):
        """Test suspicious IP detection"""
        # Add multiple failed attempts from same IP
        for i in range(4):
            attempt = LoginAttempt('user1', '192.168.1.100', datetime.now())
            self.manager.add_attempt(attempt)
            self.manager.mark_failed('user1', '192.168.1.100')
        
        suspicious = self.manager.get_suspicious_ips('user1')
        
        self.assertTrue(len(suspicious) > 0)
        self.assertEqual(suspicious[0][0], '192.168.1.100')
        self.assertGreaterEqual(suspicious[0][1], 3)
    
    def test_hourly_activity(self):
        """Test hourly activity breakdown"""
        # Add attempts at different hours
        for i in range(3):
            attempt = LoginAttempt('user1', '192.168.1.1', datetime.now() - timedelta(hours=i))
            self.manager.add_attempt(attempt)
            self.manager.mark_success('user1', '192.168.1.1')
        
        hourly = self.manager.get_hourly_activity('user1')
        
        self.assertIn('hours', hourly)
        self.assertIn('successful', hourly)
        self.assertIn('failed', hourly)
    
    def test_ip_summary(self):
        """Test IP summary generation"""
        # Add attempts from different IPs
        for ip in ['192.168.1.1', '192.168.1.2', '192.168.1.3']:
            for i in range(2):
                attempt = LoginAttempt('user1', ip, datetime.now() - timedelta(minutes=i))
                self.manager.add_attempt(attempt)
                self.manager.mark_success('user1', ip)
        
        summary = self.manager.get_ip_summary('user1')
        
        self.assertEqual(len(summary), 3)
        self.assertTrue(all('ip' in s for s in summary))


class TestSecurityAnalyzer(unittest.TestCase):
    """Test cases for SecurityAnalyzer"""
    
    def setUp(self):
        """Create analyzer and manager"""
        self.manager = LoginAttemptManager()
        self.analyzer = SecurityAnalyzer(self.manager)
    
    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        # Add some failed attempts
        for i in range(3):
            attempt = LoginAttempt('user1', '192.168.1.1', datetime.now())
            self.manager.add_attempt(attempt)
            self.manager.mark_failed('user1', '192.168.1.1')
        
        risk_score = self.analyzer.calculate_risk_score('user1')
        
        self.assertGreater(risk_score, 0)
        self.assertLessEqual(risk_score, 100)
    
    def test_security_recommendations(self):
        """Test security recommendations"""
        # Create high-risk scenario
        for i in range(5):
            attempt = LoginAttempt('user1', '192.168.1.1', datetime.now())
            self.manager.add_attempt(attempt)
            self.manager.mark_failed('user1', '192.168.1.1')
        
        recommendations = self.analyzer.get_security_recommendations('user1')
        
        self.assertTrue(len(recommendations) > 0)
        self.assertTrue(any('HIGH' in rec['priority'] for rec in recommendations))
    
    def test_security_report(self):
        """Test security report generation"""
        # Add some activity
        attempt = LoginAttempt('user1', '192.168.1.1', datetime.now())
        self.manager.add_attempt(attempt)
        self.manager.mark_success('user1', '192.168.1.1')
        
        report = self.analyzer.export_security_report('user1')
        
        self.assertIn('username', report)
        self.assertIn('risk_score', report)
        self.assertIn('statistics', report)
        self.assertIn('suspicious_activity', report)
        self.assertIn('recommendations', report)


class TestValidator(unittest.TestCase):
    """Test cases for Validator"""
    
    def test_valid_username(self):
        """Test valid username validation"""
        self.assertTrue(Validator.validate_username('testuser123'))
        self.assertTrue(Validator.validate_username('user_name'))
    
    def test_invalid_username(self):
        """Test invalid username validation"""
        self.assertFalse(Validator.validate_username('ab'))  # Too short
        self.assertFalse(Validator.validate_username('a' * 21))  # Too long
        self.assertFalse(Validator.validate_username('user@name'))  # Invalid chars
    
    def test_valid_email(self):
        """Test valid email validation"""
        self.assertTrue(Validator.validate_email('test@example.com'))
        self.assertTrue(Validator.validate_email('user.name+tag@example.co.uk'))
    
    def test_invalid_email(self):
        """Test invalid email validation"""
        self.assertFalse(Validator.validate_email('notanemail'))
        self.assertFalse(Validator.validate_email('user@'))
    
    def test_valid_password(self):
        """Test valid password validation"""
        self.assertTrue(Validator.validate_password('TestPass123'))
        self.assertTrue(Validator.validate_password('MySecure1Pass'))
    
    def test_invalid_password(self):
        """Test invalid password validation"""
        self.assertFalse(Validator.validate_password('short'))  # Too short
        self.assertFalse(Validator.validate_password('allsmall123'))  # No uppercase
        self.assertFalse(Validator.validate_password('ALLUPPER123'))  # No lowercase
        self.assertFalse(Validator.validate_password('NoDigits'))  # No digits
    
    def test_valid_ip_address(self):
        """Test valid IP address validation"""
        self.assertTrue(Validator.validate_ip_address('192.168.1.1'))
        self.assertTrue(Validator.validate_ip_address('127.0.0.1'))
    
    def test_invalid_ip_address(self):
        """Test invalid IP address validation"""
        self.assertFalse(Validator.validate_ip_address('256.1.1.1'))  # Out of range
        self.assertFalse(Validator.validate_ip_address('192.168.1'))  # Incomplete


if __name__ == '__main__':
    unittest.main()
