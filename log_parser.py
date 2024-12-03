import re, csv
from collections import Counter

def analyze_log(filename):
    ip_hits, endpoints, failed_logins = Counter(), Counter(), Counter()
    pattern = r'(\d+\.\d+\.\d+\.\d+).*?"[A-Z]+ ([^"\s]+).*?(\d{3})'
    
    for line in open(filename):
        if match := re.search(pattern, line):
            ip, endpoint, status = match.groups()
            ip_hits[ip] += 1
            endpoints[endpoint] += 1
            if status == '401' and '/login' in endpoint:
                failed_logins[ip] += 1

    # Terminal output
    print("\n=== Log Analysis Results ===\n")
    
    print("1. Requests per IP")
    print("-" * 40)
    print("IP Address           Request Count")
    print("-" * 40)
    for ip, count in ip_hits.most_common():
        print(f"{ip:<20} {count}")

    print("\n2. Most Accessed Endpoints")
    print("-" * 40)
    print("Endpoint                                  Access Count")
    print("-" * 40)
    for endpoint, count in endpoints.most_common(5):  # Show top 5 endpoints
        print(f"{endpoint:<40} {count}")

    print("\n3. Suspicious Activity (Failed Logins)")
    print("-" * 45)
    print("IP Address           Failed Login Count")
    print("-" * 45)
    suspicious = {ip: count for ip, count in failed_logins.items() if count >= 3}
    for ip, count in suspicious.items():
        print(f"{ip:<20} {count}")

    # CSV output with sections
    with open('log_analysis_results.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Requests per IP section
        writer.writerow(['=== Requests per IP ==='])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_hits.most_common():
            writer.writerow([ip, count])
        
        # Most Accessed Endpoints section
        writer.writerow([])  # Empty row for separation
        writer.writerow(['=== Most Accessed Endpoints ==='])
        writer.writerow(['Endpoint', 'Access Count'])
        for endpoint, count in endpoints.most_common(5):
            writer.writerow([endpoint, count])
        
        # Suspicious Activity section
        writer.writerow([])  # Empty row for separation
        writer.writerow(['=== Suspicious Activity ==='])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious.items():
            writer.writerow([ip, count])

if __name__ == "__main__":
    try:
        analyze_log("sample.log")
    except Exception as e:
        print(f"Error: {e}")
