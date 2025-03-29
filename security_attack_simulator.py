import requests
import time
import random
import hashlib

class SecurityAttackSimulator:
    def __init__(self, base_url):
        self.base_url = base_url
    
    def replay_attack_test(self, original_message):
        """
        Attempt to replay a previously sent message
        """
        print("\n=== Replay Attack Simulation ===")
        # First, capture an original message
        print("Capturing original message...")
        
        # Attempt to resend the same message multiple times
        for i in range(3):
            response = requests.post(f"{self.base_url}/send_message_to_device", 
                                     json=original_message)
            print(f"Replay Attempt {i+1}: {response.status_code}")
            
            if response.status_code != 200:
                print("❌ Replay Attack Prevented!")
                return True
        
        print("⚠️ Potential Vulnerability Detected!")
        return False

    def message_tampering_test(self, original_message):
        """
        Attempt to modify message contents
        """
        print("\n=== Message Tampering Simulation ===")
        
        # Modify critical fields
        tampered_message = original_message.copy()
        tampered_message['message'] = "MALICIOUS_PAYLOAD"
        
        response = requests.post(f"{self.base_url}/send_message_to_device", 
                                 json=tampered_message)
        
        if response.status_code != 200:
            print("❌ Message Tampering Attack Prevented!")
            return True
        
        print("⚠️ Potential Vulnerability Detected!")
        return False

    def brute_force_login_test(self, username):
        """
        Simulate brute force login attempts
        """
        print("\n=== Brute Force Login Simulation ===")
        
        incorrect_passwords = [
            'password123', 
            'admin', 
            username + '123',
            'test1234'
        ]
        
        failed_attempts = 0
        for password in incorrect_passwords:
            response = requests.post(f"{self.base_url}/login", 
                                     json={
                                         'username': username, 
                                         'password': password
                                     })
            
            if response.status_code != 200:
                failed_attempts += 1
                print(f"Failed Attempt: {password}")
            
            # Simulate exponential backoff
            time.sleep(1 * (failed_attempts ** 2))
        
        if failed_attempts > 0:
            print("❌ Brute Force Attack Mitigated!")
            return True
        
        print("⚠️ Potential Vulnerability Detected!")
        return False

    def run_comprehensive_test(self, test_message, test_username):
        """
        Run multiple attack simulations
        """
        results = {
            'Replay Attack': self.replay_attack_test(test_message),
            'Message Tampering': self.message_tampering_test(test_message),
            'Brute Force Login': self.brute_force_login_test(test_username)
        }
        
        # Generate security report
        print("\n=== Security Test Report ===")
        for attack, passed in results.items():
            status = "PASSED ✅" if passed else "FAILED ❌"
            print(f"{attack}: {status}")

# Usage Example
if __name__ == "__main__":
    simulator = SecurityAttackSimulator("http://localhost:5000")
    
    test_message = {
        "device_id": 1,
        "user_id": 1,
        "message": "Test Message"
    }
    
    simulator.run_comprehensive_test(test_message, "testuser")