"""
Security Analyzer - Detects suspicious login patterns and anomalies
Uses algorithms: Pattern matching, statistical analysis, geolocation estimation
"""

from datetime import datetime, timedelta
from collections import defaultdict
import math


class SecurityAnalyzer:
    """Analyzes login attempts for suspicious patterns"""
    
    def __init__(self, login_manager):
        self.login_manager = login_manager
        self.brute_force_threshold = 5  # Attempts in 10 minutes
        self.unusual_location_threshold = 3  # New IPs in 24 hours
    
    def detect_suspicious_activity(self, username: str) -> dict:
        """
        Comprehensive suspicious activity detection
        Returns dictionary with various anomaly flags
        """
        return {
            'suspicious_ips': self.login_manager.get_suspicious_ips(username),
            'brute_force_detected': self.login_manager.detect_brute_force_pattern(username),
            'unusual_locations': self._detect_unusual_locations(username),
            'time_anomalies': self._detect_time_anomalies(username)
        }
    
    def _detect_unusual_locations(self, username: str) -> list:
        """
        Detect unusual locations (unusual IP changes)
        Algorithm: Clustering with distance metric
        """
        if username not in self.login_manager.attempts:
            return []
        
        attempts = self.login_manager.attempts[username]
        last_24h = datetime.now() - timedelta(hours=24)
        recent_attempts = [a for a in attempts if a.timestamp > last_24h]
        
        # Get unique IPs from recent attempts
        unique_ips = {}
        for attempt in recent_attempts:
            if attempt.status == 'success' and attempt.ip_address not in unique_ips:
                unique_ips[attempt.ip_address] = attempt.timestamp
        
        # If more than threshold unique IPs, flag as unusual
        if len(unique_ips) > self.unusual_location_threshold:
            return list(unique_ips.keys())
        
        return []
    
    def _detect_time_anomalies(self, username: str) -> list:
        """
        Detect unusual login times
        Algorithm: Time-based pattern analysis
        """
        if username not in self.login_manager.attempts:
            return []
        
        attempts = self.login_manager.attempts[username]
        successful_attempts = [a for a in attempts if a.status == 'success']
        
        if len(successful_attempts) < 3:
            return []
        
        # Analyze login hours
        hour_distribution = defaultdict(int)
        for attempt in successful_attempts[-100:]:  # Last 100 successful logins
            hour = attempt.timestamp.hour
            hour_distribution[hour] += 1
        
        # Find normal hours (most frequent)
        if hour_distribution:
            normal_hours = sorted(hour_distribution.items(), key=lambda x: x[1], reverse=True)[:3]
            normal_hour_set = {h[0] for h in normal_hours}
            
            # Check if recent attempts deviate significantly
            last_attempts = successful_attempts[-5:]
            anomalies = []
            for attempt in last_attempts:
                if attempt.timestamp.hour not in normal_hour_set:
                    anomalies.append({
                        'timestamp': attempt.timestamp.isoformat(),
                        'hour': attempt.timestamp.hour,
                        'type': 'unusual_hour'
                    })
            
            return anomalies
        
        return []
    
    def calculate_risk_score(self, username: str) -> float:
        """
        Calculate overall risk score (0-100)
        Algorithm: Weighted scoring system
        """
        score = 0.0
        
        # Factor 1: Failed attempts (weight 30%)
        stats = self.login_manager.get_user_statistics(username)
        if stats['total_attempts'] > 0:
            failure_rate = (stats['failed_attempts'] / stats['total_attempts']) * 100
            score += min(failure_rate, 100) * 0.3
        
        # Factor 2: Recent failures (weight 25%)
        recent_failed = stats['recent_failed']
        score += min(recent_failed * 5, 100) * 0.25
        
        # Factor 3: Brute force pattern (weight 25%)
        if self.login_manager.detect_brute_force_pattern(username):
            score += 25
        
        # Factor 4: Suspicious IPs (weight 20%)
        suspicious_ips = len(self.login_manager.get_suspicious_ips(username))
        score += min(suspicious_ips * 10, 100) * 0.2
        
        return round(score, 2)
    
    def get_security_recommendations(self, username: str) -> list:
        """
        Generate security recommendations based on activity
        Algorithm: Rule-based recommendation system
        """
        recommendations = []
        risk_score = self.calculate_risk_score(username)
        
        stats = self.login_manager.get_user_statistics(username)
        suspicious = self.detect_suspicious_activity(username)
        
        # High risk recommendations
        if risk_score >= 70:
            recommendations.append({
                'priority': 'HIGH',
                'message': 'Your account shows high-risk activity. Consider changing your password.'
            })
        
        # Brute force detected
        if suspicious['brute_force_detected']:
            recommendations.append({
                'priority': 'HIGH',
                'message': 'Multiple failed login attempts detected in short time. Account may be under attack.'
            })
        
        # Unusual locations
        if suspicious['unusual_locations']:
            recommendations.append({
                'priority': 'MEDIUM',
                'message': f'Logins from {len(suspicious["unusual_locations"])} unusual locations in last 24 hours. Review recent activity.'
            })
        
        # Multiple IPs
        if stats['unique_ips'] > 5:
            recommendations.append({
                'priority': 'MEDIUM',
                'message': f'Logins from {stats["unique_ips"]} different IPs. Ensure all are trusted devices.'
            })
        
        # Time anomalies
        if suspicious['time_anomalies']:
            recommendations.append({
                'priority': 'LOW',
                'message': 'Logins at unusual times detected. Verify if this was intentional.'
            })
        
        # Low success rate
        if stats['total_attempts'] > 10 and stats['success_rate'] < 50:
            recommendations.append({
                'priority': 'MEDIUM',
                'message': 'High failure rate. Check if password is correct or if account is compromised.'
            })
        
        return recommendations
    
    def export_security_report(self, username: str) -> dict:
        """Generate comprehensive security report"""
        stats = self.login_manager.get_user_statistics(username)
        suspicious = self.detect_suspicious_activity(username)
        recommendations = self.get_security_recommendations(username)
        
        return {
            'username': username,
            'generated_at': datetime.now().isoformat(),
            'risk_score': self.calculate_risk_score(username),
            'statistics': stats,
            'suspicious_activity': suspicious,
            'recommendations': recommendations
        }
