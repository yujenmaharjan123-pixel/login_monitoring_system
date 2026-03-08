"""
System Logger - Logs application events
"""

from datetime import datetime
import os


class SystemLogger:
    """Logs system events to file and console"""
    
    def __init__(self, log_path):
        self.log_path = log_path
        self.ensure_log_file()
    
    def ensure_log_file(self):
        """Ensure log file and directory exist"""
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        if not os.path.exists(self.log_path):
            open(self.log_path, 'a').close()
    
    def log(self, message: str, level: str = 'INFO') -> None:
        """Log message with timestamp and level"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        formatted_message = f"[{timestamp}] [{level}] {message}"
        
        # Write to file
        try:
            with open(self.log_path, 'a') as f:
                f.write(formatted_message + '\n')
        except Exception as e:
            print(f"Failed to write to log file: {e}")
        
        # Print to console
        print(formatted_message)
    
    def get_recent_logs(self, lines: int = 100) -> list:
        """Get recent log lines"""
        try:
            with open(self.log_path, 'r') as f:
                all_lines = f.readlines()
            return all_lines[-lines:]
        except:
            return []
