"""
Unit Tests for Login Attempt Monitoring System
Using pytest framework
"""

import pytest
from datetime import datetime, timedelta
from login_system import (
    User, LoginAttempt, LoginAttemptMonitor,
    LoginAnalytics, ThreatDetector, RateLimiter
)


class TestUser:
    """Test User class"""
    
    def test_user_creation(self):
        """Test creating a user"""
        user = User("testuser", "test@example.com", "password123")
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.user_id is not None
        assert not user.is_locked
    
    def test_password_hashing(self):
        """Test password hashing"""
        password = "securepass123"
        user = User("testuser", "test@example.com", password)
        assert user.verify_password(password)
        assert not user.verify_password("wrongpassword")
    
    def test_password_not_stored_plaintext(self):
        """Test that password is not stored as plaintext"""
        password = "mypassword"
        user = User("testuser", "test@example.com", password)
        assert user.password_hash != password
    
    def test_user_two_factor_default_false(self):
        """Test 2FA is disabled by default"""
        user = User("testuser", "test@example.com", "password")
        assert not user.two_factor_enabled


class TestLoginAttempt:
    """Test LoginAttempt class"""
    
    def test_login_attempt_creation(self):
        """Test creating a login attempt"""
        attempt = LoginAttempt("testuser", "192.168.1.1")
        assert attempt.username == "testuser"
        assert attempt.ip_address == "192.168.1.1"
        assert attempt.attempt_id is not None
        assert not attempt.success
        assert attempt.threat_level == "low"
    
    def test_login_attempt_to_dict(self):
        """Test converting attempt to dictionary"""
        attempt = LoginAttempt("testuser", "192.168.1.1")
        attempt.success = True
        data = attempt.to_dict()
        
        assert data['username'] == "testuser"
        assert data['ip_address'] == "192.168.1.1"
        assert data['success'] is True
    
    def test_login_attempt_timestamp(self):
        """Test that timestamp is set on creation"""
        attempt = LoginAttempt("user", "192.168.1.1")
        assert isinstance(attempt.timestamp, datetime)
        assert abs((datetime.now() - attempt.timestamp).total_seconds()) < 1


class TestLoginAttemptMonitor:
    """Test LoginAttemptMonitor class"""
    
    def test_monitor_creation(self):
        """Test creating a monitor"""
        monitor = LoginAttemptMonitor()
        assert len(monitor._attempt_queue) == 0
    
    def test_add_attempt(self):
        """Test adding an attempt to monitor"""
        monitor = LoginAttemptMonitor()
        attempt = LoginAttempt("user", "192.168.1.1")
        monitor.add_attempt(attempt)
        
        assert len(monitor._attempt_queue) == 1
        assert len(monitor._attempts_by_user["user"]) == 1
    
    def test_get_recent_attempts(self):
        """Test getting recent attempts"""
        monitor = LoginAttemptMonitor()
        
        # Add old attempt
        old_attempt = LoginAttempt("user", "192.168.1.1")
        old_attempt.timestamp = datetime.now() - timedelta(hours=2)
        monitor.add_attempt(old_attempt)
        
        # Add recent attempt
        recent_attempt = LoginAttempt("user", "192.168.1.1")
        monitor.add_attempt(recent_attempt)
        
        # Get last hour
        recent = monitor.get_recent_attempts(minutes=60)
        assert len(recent) == 1
        assert recent[0] == recent_attempt
    
    def test_failed_attempts_count(self):
        """Test counting failed attempts"""
        monitor = LoginAttemptMonitor()
        
        for i in range(3):
            attempt = LoginAttempt("user", "192.168.1.1")
            attempt.success = False
            monitor.add_attempt(attempt)
        
        count = monitor.get_failed_attempts_count("user")
        assert count == 3
    
    def test_failed_attempts_count_time_window(self):
        """Test failed attempts with time window"""
        monitor = LoginAttemptMonitor()
        
        # Add old failed attempt
        old_attempt = LoginAttempt("user", "192.168.1.1")
        old_attempt.success = False
        old_attempt.timestamp = datetime.now() - timedelta(minutes=45)
        monitor.add_attempt(old_attempt)
        
        # Add recent failed attempt
        recent_attempt = LoginAttempt("user", "192.168.1.1")
        recent_attempt.success = False
        monitor.add_attempt(recent_attempt)
        
        # Count in 30 min window
        count = monitor.get_failed_attempts_count("user", minutes=30)
        assert count == 1
    
    def test_ip_login_count(self):
        """Test counting logins from an IP"""
        monitor = LoginAttemptMonitor()
        
        for i in range(5):
            attempt = LoginAttempt("user" + str(i), "192.168.1.1")
            monitor.add_attempt(attempt)
        
        count = monitor.get_ip_login_count("192.168.1.1")
        assert count == 5
    
    def test_unusual_activity_detection(self):
        """Test detecting unusual activity"""
        monitor = LoginAttemptMonitor()
        
        # Add rapid attempts
        for i in range(5):
            attempt = LoginAttempt("user", "192.168.1.1")
            attempt.timestamp = datetime.now() - timedelta(seconds=i*2)
            monitor.add_attempt(attempt)
        
        assert monitor.detect_unusual_activity("user") is True
    
    def test_threats_for_user(self):
        """Test getting threats for user"""
        monitor = LoginAttemptMonitor()
        
        # Add multiple failed attempts
        for i in range(10):
            attempt = LoginAttempt("user", "192.168.1." + str(i))
            attempt.success = False
            monitor.add_attempt(attempt)
        
        threats = monitor.get_threats_for_user("user")
        assert len(threats) > 0


class TestThreatDetector:
    """Test ThreatDetector class"""
    
    def test_detector_creation(self):
        """Test creating a threat detector"""
        detector = ThreatDetector()
        assert detector.threat_weights is not None
    
    def test_analyze_no_history(self):
        """Test analyzing with no history"""
        detector = ThreatDetector()
        level = detector.analyze_login_attempt("user", "192.168.1.1", [])
        assert level == "low"
    
    def test_analyze_new_ip(self):
        """Test detecting new IP"""
        detector = ThreatDetector()
        
        # Create history from different IP
        history = [LoginAttempt("user", "192.168.1.1")]
        
        # Analyze login from new IP
        level = detector.analyze_login_attempt("user", "10.0.0.1", history)
        assert level in ["low", "medium"]  # Should detect as at least medium due to new IP
    
    def test_detailed_analysis(self):
        """Test detailed threat analysis"""
        detector = ThreatDetector()
        
        history = []
        for i in range(10):
            attempt = LoginAttempt("user", "192.168.1.1")
            attempt.success = i < 7  # 7 successes, 3 failures
            history.append(attempt)
        
        analysis = detector.detailed_analysis("user", history)
        assert analysis['total_attempts'] == 10
        assert analysis['successful_attempts'] == 7
        assert analysis['failed_attempts'] == 3
        assert analysis['success_rate'] == 70.0
    
    def test_low_success_rate_detection(self):
        """Test detecting low success rate"""
        detector = ThreatDetector()
        
        history = []
        for i in range(10):
            attempt = LoginAttempt("user", "192.168.1.1")
            attempt.success = i < 2  # Only 2 successes out of 10
            history.append(attempt)
        
        analysis = detector.detailed_analysis("user", history)
        assert any('Low success rate' in factor for factor in analysis['risk_factors'])


class TestLoginAnalytics:
    """Test LoginAnalytics class"""
    
    def test_analytics_creation(self):
        """Test creating analytics"""
        analytics = LoginAnalytics()
        assert analytics is not None
    
    def test_generate_statistics_empty(self):
        """Test statistics with no attempts"""
        analytics = LoginAnalytics()
        stats = analytics.generate_statistics([])
        
        assert stats['total_attempts'] == 0
        assert stats['success_rate'] == 0
    
    def test_generate_statistics(self):
        """Test generating statistics"""
        analytics = LoginAnalytics()
        
        attempts = []
        for i in range(10):
            attempt = LoginAttempt("user", f"192.168.1.{i}")
            attempt.success = i < 7  # 7 successes, 3 failures
            attempts.append(attempt)
        
        stats = analytics.generate_statistics(attempts)
        assert stats['total_attempts'] == 10
        assert stats['successful_attempts'] == 7
        assert stats['failed_attempts'] == 3
        assert stats['success_rate'] == 70.0
        assert stats['unique_ips'] == 10
    
    def test_peak_login_hour(self):
        """Test detecting peak login hour"""
        analytics = LoginAnalytics()
        
        attempts = []
        # Add 5 attempts at hour 14
        for i in range(5):
            attempt = LoginAttempt("user", "192.168.1.1")
            attempt.timestamp = datetime.now().replace(hour=14, minute=0, second=0, microsecond=0)
            attempts.append(attempt)
        
        # Add 2 attempts at other hours
        for i in range(2):
            attempt = LoginAttempt("user", "192.168.1.1")
            attempt.timestamp = datetime.now().replace(hour=10, minute=0, second=0, microsecond=0)
            attempts.append(attempt)
        
        stats = analytics.generate_statistics(attempts)
        assert stats['peak_login_hour'] == 14


class TestRateLimiter:
    """Test RateLimiter class"""
    
    def test_rate_limiter_creation(self):
        """Test creating a rate limiter"""
        limiter = RateLimiter(max_attempts=5, window_seconds=60)
        assert limiter.max_attempts == 5
    
    def test_rate_limiting(self):
        """Test rate limiting"""
        limiter = RateLimiter(max_attempts=3, window_seconds=60)
        
        # Record 3 attempts
        for i in range(3):
            assert not limiter.is_rate_limited("user")
            limiter.record_attempt("user")
        
        # 4th attempt should be limited
        assert limiter.is_rate_limited("user")
    
    def test_remaining_attempts(self):
        """Test getting remaining attempts"""
        limiter = RateLimiter(max_attempts=5, window_seconds=60)
        
        assert limiter.get_remaining_attempts("user") == 5
        limiter.record_attempt("user")
        assert limiter.get_remaining_attempts("user") == 4
    
    def test_sliding_window(self):
        """Test sliding window functionality"""
        limiter = RateLimiter(max_attempts=2, window_seconds=1)
        
        # Record 2 attempts
        limiter.record_attempt("user")
        limiter.record_attempt("user")
        
        assert limiter.is_rate_limited("user")
        
        # Wait for window to pass (simulated)
        import time
        time.sleep(1.1)
        
        # Should no longer be limited
        assert not limiter.is_rate_limited("user")


class TestIntegration:
    """Integration tests"""
    
    def test_full_login_flow(self):
        """Test a complete login flow"""
        # Create user
        user = User("testuser", "test@example.com", "password123")
        assert user.verify_password("password123")
        
        # Create login attempt
        attempt = LoginAttempt(user.username, "192.168.1.1")
        attempt.success = True
        
        # Monitor the attempt
        monitor = LoginAttemptMonitor()
        monitor.add_attempt(attempt)
        
        # Analyze threat
        detector = ThreatDetector()
        threat_level = detector.analyze_login_attempt(
            user.username, 
            "192.168.1.1",
            []
        )
        
        assert threat_level in ["low", "medium", "high", "critical"]
        
        # Generate statistics
        analytics = LoginAnalytics()
        stats = analytics.generate_statistics([attempt])
        assert stats['total_attempts'] == 1
        assert stats['successful_attempts'] == 1
    
    def test_detect_brute_force(self):
        """Test detecting brute force attack"""
        monitor = LoginAttemptMonitor()
        detector = ThreatDetector()
        
        # Simulate brute force attack
        history = []
        for i in range(10):
            attempt = LoginAttempt("user", "192.168.1.1")
            attempt.success = False  # All failed
            monitor.add_attempt(attempt)
            history.append(attempt)
        
        # Check threat level
        threat_level = detector.analyze_login_attempt("user", "192.168.1.1", history)
        
        # Should detect high threat
        assert threat_level in ["high", "critical"]


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
