import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import (
    app, 
    is_user_suspended, 
    is_ip_blocked, 
    hash_password,
    USER_FAILED_ATTEMPT_THRESHOLD,
    USER_FAILED_ATTEMPT_WINDOW,
    USER_SUSPENSION_DURATION,
    IP_FAILED_ATTEMPT_THRESHOLD
)

class TestLoginSecurity(unittest.TestCase):
    
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
    
    def test_hash_password(self):
        """Test password hashing consistency"""
        password = "testpassword123"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)  # SHA-256 produces 64 char hex
    
    @patch('app.get_db_connection')
    def test_user_not_suspended_with_no_attempts(self, mock_db):
        """Test user is not suspended with zero failed attempts"""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Simulate zero failed attempts
        mock_cursor.fetchone.return_value = {
            'attempt_count': 0,
            'last_attempt': None
        }
        
        suspended, minutes = is_user_suspended('test@example.com')
        
        self.assertFalse(suspended)
        self.assertEqual(minutes, 0)
    
    @patch('app.get_db_connection')
    def test_user_suspended_after_threshold(self, mock_db):
        """Test user is suspended after exceeding threshold"""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Simulate threshold exceeded
        last_attempt = datetime.now() - timedelta(minutes=1)
        mock_cursor.fetchone.return_value = {
            'attempt_count': USER_FAILED_ATTEMPT_THRESHOLD,
            'last_attempt': last_attempt
        }
        
        suspended, minutes = is_user_suspended('test@example.com')
        
        self.assertTrue(suspended)
        self.assertGreater(minutes, 0)
    
    @patch('app.get_db_connection')
    def test_user_not_suspended_after_duration(self, mock_db):
        """Test user is not suspended after suspension duration expires"""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Simulate old failed attempts (outside suspension window)
        last_attempt = datetime.now() - timedelta(minutes=USER_SUSPENSION_DURATION + 1)
        mock_cursor.fetchone.return_value = {
            'attempt_count': USER_FAILED_ATTEMPT_THRESHOLD,
            'last_attempt': last_attempt
        }
        
        suspended, minutes = is_user_suspended('test@example.com')
        
        self.assertFalse(suspended)
        self.assertEqual(minutes, 0)
    
    @patch('app.get_db_connection')
    def test_ip_not_blocked_below_threshold(self, mock_db):
        """Test IP is not blocked below threshold"""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Simulate attempts below threshold
        mock_cursor.fetchone.return_value = {
            'attempt_count': IP_FAILED_ATTEMPT_THRESHOLD - 1
        }
        
        blocked = is_ip_blocked('1.2.3.4')
        
        self.assertFalse(blocked)
    
    @patch('app.get_db_connection')
    def test_ip_blocked_after_threshold(self, mock_db):
        """Test IP is blocked after exceeding threshold"""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Simulate threshold exceeded
        mock_cursor.fetchone.return_value = {
            'attempt_count': IP_FAILED_ATTEMPT_THRESHOLD
        }
        
        blocked = is_ip_blocked('1.2.3.4')
        
        self.assertTrue(blocked)
    
    @patch('app.get_db_connection')
    @patch('app.get_client_ip')
    @patch('app.verify_user')
    def test_login_success(self, mock_verify, mock_ip, mock_db):
        """Test successful login clears failed attempts"""
        mock_ip.return_value = '1.2.3.4'
        mock_verify.return_value = True
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        mock_cursor.fetchone.return_value = {
            'attempt_count': 0,
            'last_attempt': None
        }
        
        response = self.app.post('/api/login',
                                json={'email': 'test@example.com', 'password': 'password'},
                                headers={'X-Forwarded-For': '1.2.3.4'})
        
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('message', data)
    
    @patch('app.get_db_connection')
    @patch('app.get_client_ip')
    @patch('app.verify_user')
    def test_login_failure(self, mock_verify, mock_ip, mock_db):
        """Test failed login records attempt"""
        mock_ip.return_value = '1.2.3.4'
        mock_verify.return_value = False
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # First call for IP check, second for user suspension check, third for recording
        mock_cursor.fetchone.side_effect = [
            {'attempt_count': 0},  # IP check
            {'attempt_count': 2, 'last_attempt': datetime.now()},  # User suspension check
            None,  # verify_user result (not used, but fetchone() might be called)
            {'attempt_count': 3, 'last_attempt': datetime.now()},  # after record_failed_attempt
            {'attempt_count': 3, 'last_attempt': datetime.now()}   # second user_suspended check
        ]
                
        response = self.app.post('/api/login',
                                json={'email': 'test@example.com', 'password': 'wrongpass'},
                                headers={'X-Forwarded-For': '1.2.3.4'})
        
        self.assertEqual(response.status_code, 401)
        data = response.get_json()
        self.assertIn('error', data)
    
    @patch('app.get_db_connection')
    @patch('app.get_client_ip')
    def test_login_blocked_by_ip(self, mock_ip, mock_db):
        """Test login blocked when IP threshold exceeded"""
        mock_ip.return_value = '1.2.3.4'
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # IP is blocked
        mock_cursor.fetchone.return_value = {
            'attempt_count': IP_FAILED_ATTEMPT_THRESHOLD
        }
        
        response = self.app.post('/api/login',
                                json={'email': 'test@example.com', 'password': 'password'},
                                headers={'X-Forwarded-For': '1.2.3.4'})
        
        self.assertEqual(response.status_code, 403)
        data = response.get_json()
        self.assertIn('IP temporarily blocked', data['error'])
    
    @patch('app.get_db_connection')
    @patch('app.get_client_ip')
    def test_login_suspended_user(self, mock_ip, mock_db):
        """Test login blocked when user is suspended"""
        mock_ip.return_value = '1.2.3.4'
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # First call: IP check (not blocked), Second call: User suspension check (suspended)
        mock_cursor.fetchone.side_effect = [
            {'attempt_count': 0},  # IP not blocked
            {'attempt_count': USER_FAILED_ATTEMPT_THRESHOLD, 
             'last_attempt': datetime.now()}  # User suspended
        ]
        
        response = self.app.post('/api/login',
                                json={'email': 'test@example.com', 'password': 'password'},
                                headers={'X-Forwarded-For': '1.2.3.4'})
        
        self.assertEqual(response.status_code, 403)
        data = response.get_json()
        self.assertIn('temporarily suspended', data['error'])
    
    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = self.app.get('/api/health')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'healthy')
    
    def test_missing_credentials(self):
        """Test login with missing credentials"""
        response = self.app.post('/api/login', json={})
        self.assertEqual(response.status_code, 400)


class TestThresholdLogic(unittest.TestCase):
    """Test threshold configuration and logic"""
    
    def test_user_threshold_configuration(self):
        """Verify user threshold is set correctly"""
        self.assertEqual(USER_FAILED_ATTEMPT_THRESHOLD, 5)
        self.assertEqual(USER_FAILED_ATTEMPT_WINDOW, 5)
        self.assertEqual(USER_SUSPENSION_DURATION, 15)
    
    def test_ip_threshold_configuration(self):
        """Verify IP threshold is set correctly"""
        self.assertEqual(IP_FAILED_ATTEMPT_THRESHOLD, 100)


if __name__ == '__main__':
    unittest.main()