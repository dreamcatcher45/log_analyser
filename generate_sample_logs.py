import random
from datetime import datetime, timedelta
import ipaddress

def generate_sample_logs(filename: str, num_entries: int = 1000):
    # Sample endpoints
    endpoints = ['/home', '/login', '/api/data', '/users', '/admin', '/dashboard', '/logout']
    http_methods = ['GET', 'POST', 'PUT', 'DELETE']
    
    # Generate some "normal" IPs and some "suspicious" IPs
    normal_ips = [str(ipaddress.IPv4Address('192.168.1.1') + i) for i in range(20)]
    suspicious_ips = [str(ipaddress.IPv4Address('10.0.0.1') + i) for i in range(5)]
    
    # Generate log entries
    start_time = datetime.now() - timedelta(days=1)
    
    with open(filename, 'w') as f:
        for i in range(num_entries):
            timestamp = start_time + timedelta(seconds=i)
            
            # Decide if this should be a suspicious entry (failed login attempt)
            is_suspicious = random.random() < 0.15  # 15% chance of failed login
            
            if is_suspicious:
                ip = random.choice(suspicious_ips)
                method = 'POST'
                endpoint = '/login'
                status = 401
                message = 'Invalid credentials'
            else:
                ip = random.choice(normal_ips)
                method = random.choice(http_methods)
                endpoint = random.choice(endpoints)
                status = random.choice([200, 201, 301, 304, 400, 404, 500])
                message = 'Success' if status == 200 else 'Error'
            
            log_entry = f'{ip} - - [{timestamp:%d/%b/%Y:%H:%M:%S +0000}] "{method} {endpoint} HTTP/1.1" {status} 128 "{message}"\n'
            f.write(log_entry)

if __name__ == "__main__":
    generate_sample_logs('sample.log', num_entries=200000)  # Generate 200000 sample entries
    print("Sample log file generated successfully!")
