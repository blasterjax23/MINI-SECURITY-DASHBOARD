import unittest
import os
import sqlite3
import json
import datetime
from app import app, init_db, DB_PATH, classify_ip

class SecurityDashboardTestCase(unittest.TestCase):

    def setUp(self):
        # Configure app for testing
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # Use a separate test database path
        self.test_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_security.db")
        
        # Override the database path in the app
        import app as app_module
        app_module.DB_PATH = self.test_db_path
        
        # Initialize the test database
        init_db()

    def tearDown(self):
        # Clean up database file
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

    def test_ip_classification(self):
        # Loopback
        self.assertEqual(classify_ip("127.0.0.1"), "Loopback")
        self.assertEqual(classify_ip("::1"), "Loopback")
        
        # Private
        self.assertEqual(classify_ip("10.0.0.1"), "Private")
        self.assertEqual(classify_ip("172.16.5.5"), "Private")
        self.assertEqual(classify_ip("192.168.1.100"), "Private")
        
        # Military
        self.assertEqual(classify_ip("6.1.1.1"), "Military")
        self.assertEqual(classify_ip("214.5.5.5"), "Military")
        
        # Reserved / R&D
        self.assertEqual(classify_ip("0.0.0.0"), "Reserved/R&D")
        self.assertEqual(classify_ip("240.1.2.3"), "Reserved/R&D")
        self.assertEqual(classify_ip("100.64.1.1"), "Reserved/R&D")
        
        # Public
        self.assertEqual(classify_ip("8.8.8.8"), "Public")
        self.assertEqual(classify_ip("1.1.1.1"), "Public")
        
        # Invalid
        self.assertEqual(classify_ip("not_an_ip"), "Invalid")
        self.assertEqual(classify_ip("999.999.999.999"), "Invalid")

    def test_register_public_ip(self):
        # Registering with a public IP should succeed
        headers = {'X-Simulated-IP': '8.8.8.8'}
        payload = {'username': 'testuser', 'password': 'Password123!', 'ip_address': '8.8.8.8'}
        
        response = self.client.post('/api/register', 
                                    headers=headers, 
                                    data=json.dumps(payload),
                                    content_type='application/json')
        
        data = json.loads(response.data.decode())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['ip_type'], 'Public')

    def test_register_new_rules(self):
        headers = {'X-Simulated-IP': '8.8.8.8'}
        
        # 1. Invalid IP format -> should be blocked with 400
        payload_invalid = {'username': 'user1', 'password': 'Password123!', 'ip_address': 'invalid_ip'}
        response = self.client.post('/api/register', headers=headers, data=json.dumps(payload_invalid), content_type='application/json')
        data = json.loads(response.data.decode())
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid IP", data['message'])

        # 2. Private or Loopback IP -> should now succeed under new rules!
        payload_loopback = {'username': 'user_loopback', 'password': 'Password123!', 'ip_address': '127.0.0.1'}
        response = self.client.post('/api/register', headers=headers, data=json.dumps(payload_loopback), content_type='application/json')
        data = json.loads(response.data.decode())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['ip_type'], 'Loopback')

        # 3. IP with > 3 failed login attempts -> should be blocked!
        suspicious_ip = '192.168.1.50'
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        # Insert 4 failed login logs for this IP
        for _ in range(4):
            cursor.execute("""
                INSERT INTO login_log (username, ip_address, event_type, ip_classification)
                VALUES ('someuser', ?, 'failed', 'Private')
            """, (suspicious_ip,))
        conn.commit()
        conn.close()

        payload_suspicious = {'username': 'user_suspicious', 'password': 'Password123!', 'ip_address': suspicious_ip}
        response = self.client.post('/api/register', headers=headers, data=json.dumps(payload_suspicious), content_type='application/json')
        data = json.loads(response.data.decode())
        self.assertEqual(response.status_code, 403)
        self.assertIn("more than 3 failed login attempts", data['message'])

        # Verify no user was created for blocked attempt
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = 'user_suspicious'")
        self.assertIsNone(cursor.fetchone())
        conn.close()

    def test_login_lockout_after_three_failures(self):
        # Register a valid user
        headers = {'X-Simulated-IP': '8.8.8.8'}
        payload = {'username': 'lockuser', 'password': 'Password123!', 'ip_address': '8.8.8.8'}
        self.client.post('/api/register', headers=headers, data=json.dumps(payload), content_type='application/json')
        
        # Try to login with incorrect password 3 times
        fail_payload = {'username': 'lockuser', 'password': 'WrongPassword'}
        for i in range(1, 4):
            response = self.client.post('/api/login', headers=headers, data=json.dumps(fail_payload), content_type='application/json')
            data = json.loads(response.data.decode())
            
            if i < 3:
                self.assertEqual(response.status_code, 401)
                self.assertEqual(data['remaining_attempts'], 3 - i)
            else:
                self.assertEqual(response.status_code, 401)
                self.assertEqual(data['remaining_attempts'], 0)
                self.assertIn('locked', data['message'])

        # The 4th attempt should yield a 403 Forbidden lock message
        response = self.client.post('/api/login', headers=headers, data=json.dumps(fail_payload), content_type='application/json')
        data = json.loads(response.data.decode())
        self.assertEqual(response.status_code, 403)
        self.assertIn('locked', data['message'])

    def test_reset_password(self):
        # Register user
        headers = {'X-Simulated-IP': '8.8.8.8'}
        payload = {'username': 'resetuser', 'password': 'Password123!', 'ip_address': '8.8.8.8'}
        self.client.post('/api/register', headers=headers, data=json.dumps(payload), content_type='application/json')
        
        # Reset password
        reset_payload = {
            'username': 'resetuser',
            'new_password': 'NewPassword123!',
            'confirm_password': 'NewPassword123!'
        }
        response = self.client.post('/api/reset-password', headers=headers, data=json.dumps(reset_payload), content_type='application/json')
        data = json.loads(response.data.decode())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['status'], 'success')
        
        # Try logging in with the new password
        login_payload = {'username': 'resetuser', 'password': 'NewPassword123!'}
        response = self.client.post('/api/login', headers=headers, data=json.dumps(login_payload), content_type='application/json')
        data = json.loads(response.data.decode())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['status'], 'success')

if __name__ == '__main__':
    unittest.main()
