"""
Login Attempt Monitoring System
Main Flask Application with OOP Architecture
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from datetime import datetime, timedelta
from functools import wraps
import secrets
import hashlib
from login_system import (
    User, LoginAttempt, LoginAttemptMonitor, 
    LoginAnalytics, ThreatDetector, NotificationManager
)
from database import Database
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
CORS(app)

# Initialize database and monitoring system
db = Database()
monitor = LoginAttemptMonitor()
analytics = LoginAnalytics()
threat_detector = ThreatDetector()
notification_manager = NotificationManager()


def login_required(f):
    """Decorator to protect routes requiring authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration endpoint"""
    if request.method == 'GET':
        return render_template('register.html')
    
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')

        # Validation
        if not username or len(username) < 3:
            return jsonify({'success': False, 'message': 'Username must be at least 3 characters'}), 400
        
        if not email or '@' not in email:
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400

        # Check if user exists
        if db.get_user(username):
            return jsonify({'success': False, 'message': 'Username already exists'}), 409

        # Create user
        user = User(username, email, password)
        if db.save_user(user):
            logger.info(f"New user registered: {username}")
            return jsonify({'success': True, 'message': 'Registration successful. Please login.'}), 201
        else:
            return jsonify({'success': False, 'message': 'Registration failed'}), 500

    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login endpoint with monitoring"""
    if request.method == 'GET':
        return render_template('login.html')
    
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        ip_address = request.remote_addr

        # Create login attempt record
        attempt = LoginAttempt(username, ip_address)
        
        # Check for threats before authentication
        threat_level = threat_detector.analyze_login_attempt(
            username, ip_address, db.get_login_history(username)
        )
        attempt.threat_level = threat_level

        # Authenticate user
        user = db.get_user(username)
        
        if user and user.verify_password(password):
            # Successful login
            attempt.success = True
            attempt.timestamp = datetime.now()
            
            # Save attempt
            db.save_login_attempt(attempt)
            monitor.add_attempt(attempt)
            
            # Create session
            session['user_id'] = user.user_id
            session['username'] = user.username
            
            logger.info(f"Successful login: {username} from {ip_address}")
            
            # Send notification if threat detected
            if threat_level in ['medium', 'high']:
                notification_manager.send_notification(
                    user.email,
                    f"Login detected from {ip_address} with threat level: {threat_level}"
                )
            
            return jsonify({'success': True, 'message': 'Login successful'}), 200
        else:
            # Failed login
            attempt.success = False
            attempt.timestamp = datetime.now()
            
            # Save failed attempt
            db.save_login_attempt(attempt)
            monitor.add_attempt(attempt)
            
            # Check if account should be locked
            failed_count = monitor.get_failed_attempts_count(username, minutes=30)
            
            logger.warning(f"Failed login attempt: {username} from {ip_address}")
            
            if failed_count >= 5:
                db.lock_user_account(username)
                return jsonify({
                    'success': False,
                    'message': 'Account locked due to multiple failed attempts. Please contact support.'
                }), 403
            
            return jsonify({
                'success': False,
                'message': f'Invalid credentials. ({failed_count}/5 attempts)',
                'attempts_left': 5 - failed_count
            }), 401

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html')


@app.route('/api/dashboard-data')
@login_required
def get_dashboard_data():
    """Get dashboard statistics"""
    try:
        username = session['username']
        
        # Get recent login attempts
        recent_attempts = db.get_login_history(username, limit=20)
        
        # Get analytics
        stats = analytics.generate_statistics(recent_attempts)
        
        # Get threat alerts
        threats = monitor.get_threats_for_user(username)
        
        return jsonify({
            'statistics': stats,
            'recent_attempts': [
                {
                    'timestamp': attempt.timestamp.isoformat(),
                    'ip_address': attempt.ip_address,
                    'success': attempt.success,
                    'threat_level': attempt.threat_level
                }
                for attempt in recent_attempts
            ],
            'threats': threats
        }), 200
    except Exception as e:
        logger.error(f"Dashboard data error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error fetching data'}), 500


@app.route('/api/login-history')
@login_required
def login_history():
    """Get detailed login history"""
    try:
        username = session['username']
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 50, type=int)
        
        attempts = db.get_login_history(username, limit=limit, offset=(page-1)*limit)
        
        return jsonify({
            'data': [
                {
                    'id': attempt.attempt_id,
                    'timestamp': attempt.timestamp.isoformat(),
                    'ip_address': attempt.ip_address,
                    'success': attempt.success,
                    'threat_level': attempt.threat_level
                }
                for attempt in attempts
            ],
            'page': page
        }), 200
    except Exception as e:
        logger.error(f"Login history error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error fetching history'}), 500


@app.route('/api/threat-analysis')
@login_required
def threat_analysis():
    """Get threat analysis"""
    try:
        username = session['username']
        
        # Get analysis
        analysis = threat_detector.detailed_analysis(username, db.get_login_history(username))
        
        return jsonify(analysis), 200
    except Exception as e:
        logger.error(f"Threat analysis error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error analyzing threats'}), 500


@app.route('/api/location-map')
@login_required
def location_map():
    """Get login locations for mapping"""
    try:
        username = session['username']
        attempts = db.get_login_history(username, limit=100)
        
        # Group by IP address
        locations = {}
        for attempt in attempts:
            if attempt.ip_address not in locations:
                locations[attempt.ip_address] = {
                    'count': 0,
                    'latest': attempt.timestamp.isoformat()
                }
            locations[attempt.ip_address]['count'] += 1
        
        return jsonify(locations), 200
    except Exception as e:
        logger.error(f"Location map error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error mapping locations'}), 500


@app.route('/api/account-settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    """Manage account settings"""
    username = session['username']
    user = db.get_user(username)
    
    if request.method == 'GET':
        return jsonify({
            'username': user.username,
            'email': user.email,
            '2fa_enabled': user.two_factor_enabled,
            'login_notifications_enabled': user.login_notifications_enabled
        }), 200
    
    try:
        data = request.get_json()
        
        if 'email' in data:
            user.email = data['email']
        
        if 'two_factor_enabled' in data:
            user.two_factor_enabled = data['two_factor_enabled']
        
        if 'login_notifications_enabled' in data:
            user.login_notifications_enabled = data['login_notifications_enabled']
        
        db.update_user(user)
        logger.info(f"Settings updated for user: {username}")
        
        return jsonify({'success': True, 'message': 'Settings updated'}), 200
    except Exception as e:
        logger.error(f"Settings update error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error updating settings'}), 500


@app.route('/logout')
def logout():
    """Logout user"""
    username = session.get('username')
    session.clear()
    logger.info(f"User logged out: {username}")
    return redirect(url_for('login'))


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(error)}")
    return jsonify({'error': 'Server error'}), 500


if __name__ == '__main__':
    # Create required directories
    import os
    os.makedirs('logs', exist_ok=True)
    os.makedirs('data', exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
