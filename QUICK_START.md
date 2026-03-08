# Quick Start Guide - Login Attempt Monitoring System

## ⚡ 5-Minute Setup

### Step 1: Extract Files
```bash
unzip login_monitoring_system.zip
cd login_monitoring_system
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run the Application
```bash
cd app
python app.py
```

### Step 4: Open in Browser
Navigate to: **http://localhost:5000**

---

## 🚀 Getting Started

### Create an Account
1. Click **"Register here"** on login page
2. Enter username (e.g., `demouser`)
3. Enter email (e.g., `demo@example.com`)
4. Create strong password (e.g., `SecurePass123`)
5. Click **Register**

### Login
1. Enter your username and password
2. Click **Login**
3. You'll see the Dashboard

### Explore Features
- **Dashboard**: View statistics and risk score
- **Activity Chart**: See 24-hour login patterns
- **Login History**: Review all login attempts
- **IP Summary**: Check devices you've logged in from
- **Suspicious Activity**: Review any alerts
- **Settings**: Adjust preferences

---

## 📊 Testing the System

### Test Account
- Username: `testuser`
- Password: `Test123456`

### Simulate Login Attempts
1. Try logging in with wrong password 5 times
2. See account get locked
3. Wait 30 minutes or check lockout status
4. View failed attempts in history

### View Test Data
- Dashboard shows multiple login attempts
- Risk score calculated based on activity
- Charts visualize 24-hour patterns
- Suspicious IPs highlighted

---

## 🧪 Run Unit Tests

```bash
# From project root directory
python -m unittest tests/test_app.py -v
```

**Expected Output**: 31 tests passing

---

## 📁 Project Structure

```
login_monitoring_system/
├── app/
│   ├── app.py              # Main Flask app
│   ├── models/
│   │   ├── user.py         # User class
│   │   ├── login_attempt.py # LoginAttempt & Manager
│   │   └── security_analyzer.py  # Security algorithms
│   └── utils/
│       ├── validators.py   # Input validation
│       └── logger.py       # Logging system
├── tests/
│   └── test_app.py         # Unit tests (31 test cases)
├── templates/
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   └── settings.html
├── README.md               # Full documentation
├── PROJECT_REPORT.md       # Detailed report
└── requirements.txt        # Dependencies
```

---

## 🔐 Key Features

### 1. Login Tracking
- Records all login attempts with timestamps
- Tracks IP addresses and login status
- Maintains comprehensive history

### 2. Security Monitoring
- Detects brute force attacks (5+ attempts in 10 min)
- Identifies suspicious IPs (>2 failed attempts)
- Flags unusual login times
- Calculates risk score (0-100)

### 3. Account Protection
- Automatic lockout after 5 failed attempts
- 30-minute lockout duration
- Password hashing (SHA256)
- Input validation

### 4. Analytics Dashboard
- Real-time statistics
- 24-hour activity charts
- IP-based summary
- Risk assessment

---

## 💻 Technical Stack

- **Backend**: Flask, Python 3.8+
- **Frontend**: HTML5, CSS3, JavaScript
- **Charts**: Chart.js
- **Testing**: unittest
- **Version Control**: Git

---

## 🔍 Important Passwords Requirements

Password must have:
- ✓ At least 8 characters
- ✓ One uppercase letter (A-Z)
- ✓ One lowercase letter (a-z)
- ✓ One number (0-9)

**Example**: `SecurePass123` ✓

---

## 🚨 Troubleshooting

| Issue | Solution |
|-------|----------|
| **Port 5000 in use** | Change port in `app.py` line 200: `port=5001` |
| **Module not found** | Run: `pip install -r requirements.txt` |
| **Template not found** | Ensure you run from `app/` directory: `cd app && python app.py` |
| **Tests fail** | Install test dependencies: `pip install unittest` |

---

## 📝 File Descriptions

### Backend Files
- **app.py**: Main Flask application with all routes
- **models/user.py**: User class with auth methods
- **models/login_attempt.py**: LoginAttempt tracking with algorithms
- **models/security_analyzer.py**: Security threat detection
- **utils/validators.py**: Input validation functions
- **utils/logger.py**: Logging system

### Frontend Files
- **templates/login.html**: Login page (470 lines)
- **templates/register.html**: Registration page (420 lines)
- **templates/dashboard.html**: Analytics dashboard (610 lines)
- **templates/settings.html**: Settings page (440 lines)

### Documentation
- **README.md**: Complete project documentation
- **PROJECT_REPORT.md**: Detailed technical report (2000+ words)
- **QUICK_START.md**: This file

---

## 📊 Test Coverage

**31 Unit Tests**:
- User model: 7 tests
- LoginAttempt: 4 tests
- LoginAttemptManager: 10 tests
- SecurityAnalyzer: 3 tests
- Validators: 7 tests

Run tests:
```bash
python -m unittest tests/test_app.py -v
```

---

## 🌐 Git Setup (Optional)

```bash
# Initialize Git
git init

# Add files
git add .

# Create initial commit
git commit -m "Initial commit: Login Attempt Monitoring System"

# Add to GitHub
git remote add origin https://github.com/username/repo.git
git branch -M main
git push -u origin main
```

---

## 📱 Features Walkthrough

### Dashboard
1. **Statistics Cards**: Total attempts, success rate, failures, unique IPs
2. **Risk Score**: 0-100 calculation based on 4 factors
3. **Activity Chart**: 24-hour line chart showing success/failure trends
4. **Status Breakdown**: Doughnut chart showing success vs failure ratio
5. **Login History**: Table with latest 20 login attempts
6. **IP Summary**: Devices and locations from which you logged in
7. **Suspicious Activity**: Alerts for detected threats

### Settings
1. **Alert Threshold**: Set when to alert (2-20 failed attempts)
2. **Email Alerts**: Enable/disable email notifications
3. **Security Tips**: Best practices for account security

---

## 🎯 Demo Workflow

1. **Register** with strong password
2. **Login** successfully → see activity on dashboard
3. **Attempt login** with wrong password 5 times
4. **Account locks** → see lockout alert
5. **Check history** → review all attempts
6. **Review recommendations** → get security advice
7. **Check settings** → adjust preferences

---

## 📞 Support

For issues:
1. Check README.md for detailed documentation
2. Review PROJECT_REPORT.md for technical details
3. Check console output for error messages
4. Ensure Python 3.8+ is installed
5. Verify all dependencies installed: `pip install -r requirements.txt`

---

## ✅ Checklist

Before submission:
- [ ] Application runs without errors
- [ ] All 31 unit tests pass
- [ ] Can register and login
- [ ] Dashboard displays correctly
- [ ] Charts render properly
- [ ] Settings page works
- [ ] Git repository initialized
- [ ] README.md complete
- [ ] PROJECT_REPORT.md submitted
- [ ] Video (10 min) recorded and uploaded to YouTube (unlisted)

---

**Version**: 1.0.0  
**Last Updated**: 2024  
**Status**: Ready for submission ✅
