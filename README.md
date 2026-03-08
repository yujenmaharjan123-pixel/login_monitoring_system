# Login Attempt Monitoring System

## Project Overview

A comprehensive web-based **Login Attempt Monitoring System** that tracks, analyzes, and monitors user login attempts with advanced threat detection capabilities. This project demonstrates object-oriented programming (OOP) principles, data structures, algorithms, and security best practices.

## Features

### Core Features
- **User Authentication**: Secure registration and login system with password hashing
- **Login Attempt Monitoring**: Real-time tracking of all login attempts
- **Threat Detection**: AI-powered threat analysis using heuristic algorithms
- **Analytics Dashboard**: Visual insights into login patterns and security
- **Login History**: Detailed records of all login attempts
- **Account Security**: Account locking after multiple failed attempts
- **Rate Limiting**: Prevent brute-force attacks

## Key Components

### OOP Architecture
- **User Class**: Manages user data with secure password hashing
- **LoginAttempt Class**: Represents individual login events
- **LoginAttemptMonitor Class**: Tracks and analyzes patterns (Queue-based)
- **ThreatDetector Class**: Analyzes security threats using scoring algorithm
- **LoginAnalytics Class**: Generates statistical insights
- **RateLimiter Class**: Implements sliding window algorithm
- **Database Class**: Manages data persistence

### Data Structures
- **Deque**: FIFO queue for login attempts
- **DefaultDict**: Organize attempts by user and IP
- **Set**: Track unique IP addresses
- **Hash Tables**: Fast lookups and sessions

### Algorithms
1. **Threat Scoring**: Multi-factor threat analysis
2. **Brute Force Detection**: Pattern recognition
3. **Sliding Window Rate Limiting**: Time-based limiting
4. **Peak Hour Detection**: Histogram analysis
5. **Success Rate Analysis**: Statistical computation

## Technology Stack

### Backend
- Python 3.8+
- Flask framework
- JSON-based storage
- Pytest for testing

### Frontend
- HTML5, CSS3
- JavaScript (ES6+)
- Chart.js for visualization

### Development
- Git & GitHub
- Virtual environments
- Security best practices

## Installation

### Prerequisites
```bash
Python 3.8+, Git, pip
```

### Setup
```bash
# Clone repository
git clone https://github.com/yourusername/login_monitoring_system.git
cd login_monitoring_system

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run application
python app.py

# Access at http://localhost:5000
```

### Run Tests
```bash
pytest test_login_system.py -v
```

## Usage

1. **Register**: Create account with username, email, password
2. **Login**: Access with credentials
3. **Dashboard**: View login statistics and patterns
4. **Monitor**: Track threats and suspicious activities
5. **Settings**: Configure notifications and security

## Project Structure
```
login_monitoring_system/
├── app.py                    # Main Flask app
├── login_system.py          # Core OOP classes
├── database.py              # Data persistence
├── test_login_system.py     # Unit tests
├── requirements.txt         # Dependencies
├── README.md                # Documentation
├── templates/
│   ├── login.html
│   ├── dashboard.html
│   └── register.html
├── data/
│   ├── users.json
│   └── login_attempts.json
└── logs/
```

## API Endpoints

- `POST /register` - Create account
- `POST /login` - User login
- `GET /dashboard` - Main dashboard
- `GET /api/dashboard-data` - Stats
- `GET /api/login-history` - History
- `GET /api/threat-analysis` - Threats
- `POST /logout` - Logout

## Testing

The project includes 30+ unit tests covering:
- User authentication
- Login attempt tracking
- Threat detection
- Analytics generation
- Rate limiting

```bash
pytest test_login_system.py -v --cov=login_system
```

## Security Features

- SHA-256 password hashing
- Account locking (5 failed attempts)
- Rate limiting (sliding window)
- Session management
- Comprehensive logging
- Threat anomaly detection

## Performance

| Operation | Complexity |
|-----------|-----------|
| Add attempt | O(1) |
| Check threats | O(n) |
| Generate stats | O(n) |
| Rate limit | O(1) |

## Git Repository Setup

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/yourusername/login_monitoring_system.git
git push -u origin main
```

## Future Enhancements

- PostgreSQL database integration
- Machine learning threat detection
- Mobile application
- LDAP/OAuth integration
- Advanced SIEM features
- Compliance certifications (GDPR, HIPAA)

## License

MIT License - See LICENSE file

## Author

[Your Name]

---

**Version**: 1.0.0  
**Last Updated**: January 2025  
**Status**: Production Ready
