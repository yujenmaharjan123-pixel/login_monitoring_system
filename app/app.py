"""
Login Attempt Monitoring System
Main Flask Application with OOP Architecture
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from datetime import datetime, timedelta
import json
import os
os.makedirs('logs', exist_ok=True)
from .models.user import User
from .models.login_attempt import LoginAttempt, LoginAttemptManager
from .models.security_analyzer import SecurityAnalyzer
from .utils.validators import Validator
from .utils.logger import SystemLogger
import hashlib

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = 'your-secret-key-change-in-production'

# Initialize managers
login_manager = LoginAttemptManager()
logger = SystemLogger('../logs/system.log')
validator = Validator()

# In-memory user storage (in production, use a database)
users = {}

# ==================== Authentication Routes ====================

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '')
            confirm_password = data.get('confirm_password', '')

            # Validation
            if not validator.validate_username(username):
                return jsonify({'success': False, 'error': 'Username must be 3-20 characters, alphanumeric'}), 400
            
            if not validator.validate_email(email):
                return jsonify({'success': False, 'error': 'Invalid email format'}), 400
            
            if not validator.validate_password(password):
                return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
            
            if password != confirm_password:
                return jsonify({'success': False, 'error': 'Passwords do not match'}), 400
            
            if username in users:
                return jsonify({'success': False, 'error': 'Username already exists'}), 400
            
            # Create new user
            user = User(username=username, email=email, password=password)
            users[username] = user
            
            logger.log(f"New user registered: {username}")
            return jsonify({'success': True, 'message': 'Registration successful! Please login.'}), 201
        
        except Exception as e:
            logger.log(f"Registration error: {str(e)}", level='ERROR')
            return jsonify({'success': False, 'error': 'Registration failed'}), 500
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '')
            client_ip = request.remote_addr

            # Record login attempt
            attempt = LoginAttempt(username=username, ip_address=client_ip, timestamp=datetime.now())
            login_manager.add_attempt(attempt)

            # Validate input
            if not username or not password:
                login_manager.mark_failed(username, client_ip)
                return jsonify({'success': False, 'error': 'Username and password required'}), 400

            # Check if user exists
            if username not in users:
                login_manager.mark_failed(username, client_ip)
                logger.log(f"Failed login attempt - User not found: {username} from {client_ip}")
                return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

            user = users[username]

            # Verify password
            if not user.verify_password(password):
                login_manager.mark_failed(username, client_ip)
                logger.log(f"Failed login attempt - Wrong password: {username} from {client_ip}")
                return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

            # Check if account is locked
            if login_manager.is_account_locked(username):
                return jsonify({
                    'success': False,
                    'error': 'Account locked due to multiple failed attempts. Try again later.'
                }), 429

            # Successful login
            login_manager.mark_success(username, client_ip)
            session['user_id'] = username
            session['login_time'] = datetime.now().isoformat()
            
            logger.log(f"Successful login: {username} from {client_ip}")
            return jsonify({'success': True, 'message': 'Login successful!'}), 200

        except Exception as e:
            logger.log(f"Login error: {str(e)}", level='ERROR')
            return jsonify({'success': False, 'error': 'Login failed'}), 500

    return render_template('login.html')


@app.route('/logout')
def logout():
    username = session.get('user_id')
    if username:
        logger.log(f"User logged out: {username}")
    session.clear()
    return redirect(url_for('login'))


# ==================== Dashboard Routes ====================

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    username = session['user_id']
    return render_template('dashboard.html', username=username)


@app.route('/api/stats')
def get_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    username = session['user_id']
    stats = login_manager.get_user_statistics(username)
    return jsonify(stats), 200


@app.route('/api/login-history')
def get_login_history():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    username = session['user_id']
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    
    attempts = login_manager.get_user_attempts(username, page=page, limit=limit)
    return jsonify({
        'attempts': [attempt.to_dict() for attempt in attempts],
        'total': login_manager.get_user_attempt_count(username)
    }), 200


@app.route('/api/suspicious-activity')
def get_suspicious_activity():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    username = session['user_id']
    analyzer = SecurityAnalyzer(login_manager)
    suspicious = analyzer.detect_suspicious_activity(username)
    
    return jsonify({
        'suspicious_ips': suspicious['suspicious_ips'],
        'brute_force_detected': suspicious['brute_force_detected'],
        'unusual_locations': suspicious['unusual_locations'],
        'time_anomalies': suspicious['time_anomalies']
    }), 200


@app.route('/api/activity-chart')
def get_activity_chart():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    username = session['user_id']
    data = login_manager.get_hourly_activity(username)
    
    return jsonify(data), 200


@app.route('/api/ip-summary')
def get_ip_summary():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    username = session['user_id']
    summary = login_manager.get_ip_summary(username)
    
    return jsonify(summary), 200


# ==================== Settings Routes ====================

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    username = session['user_id']
    user = users.get(username)
    
    return render_template('settings.html', user=user)


@app.route('/api/update-settings', methods=['POST'])
def update_settings():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        username = session['user_id']
        user = users[username]
        
        # Update alert threshold
        if 'alert_threshold' in data:
            threshold = int(data['alert_threshold'])
            if 1 <= threshold <= 20:
                user.settings['alert_threshold'] = threshold
        
        # Update email notifications
        if 'email_alerts' in data:
            user.settings['email_alerts'] = data['email_alerts']
        
        logger.log(f"Settings updated for user: {username}")
        return jsonify({'success': True, 'message': 'Settings updated successfully'}), 200
    
    except Exception as e:
        logger.log(f"Settings update error: {str(e)}", level='ERROR')
        return jsonify({'success': False, 'error': 'Failed to update settings'}), 500


# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(error):
    logger.log(f"Server error: {str(error)}", level='ERROR')
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    logger.log("Login Attempt Monitoring System started")
    app.run(debug=True, host='127.0.0.1', port=5000)
