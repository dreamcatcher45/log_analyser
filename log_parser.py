import re
import csv
from collections import Counter
from typing import Generator, Dict, Tuple
from io import DEFAULT_BUFFER_SIZE

# Precompile regex pattern for better performance
LOG_PATTERN = re.compile(r'(\d+\.\d+\.\d+\.\d+).*?"[A-Z]+ ([^"\s]+).*?(\d{3})')

def read_log_lines(filename: str, chunk_size: int = DEFAULT_BUFFER_SIZE) -> Generator[str, None, None]:
    """Generator function to read log file in chunks efficiently."""
    with open(filename, 'r', buffering=chunk_size) as f:
        for line in f:
            yield line

def analyze_log(filename: str, batch_size: int = 1000) -> Tuple[Counter, Counter, Dict[str, int]]:
    """
    Analyze log file with optimized memory usage and performance.
    Uses batch processing and efficient data structures.
    """
    ip_hits = Counter()
    endpoints = Counter()
    failed_logins = {}  # Using dict instead of Counter for failed logins as we need fewer entries
    
    for line in read_log_lines(filename):
        if match := LOG_PATTERN.search(line):
            ip, endpoint, status = match.groups()
            ip_hits[ip] += 1
            endpoints[endpoint] += 1
            if status == '401' and '/login' in endpoint:
                failed_logins[ip] = failed_logins.get(ip, 0) + 1

    return ip_hits, endpoints, failed_logins

def write_results_to_csv(ip_hits: Counter, endpoints: Counter, suspicious: Dict[str, int], 
                        output_file: str = 'log_analysis_results.csv', batch_size: int = 1000) -> None:
    """Write results to CSV in batches for better memory efficiency."""
    with open(output_file, 'w', newline='', buffering=DEFAULT_BUFFER_SIZE) as f:
        writer = csv.writer(f)
        
        # Write IP hits in batches
        writer.writerow(['=== Requests per IP ==='])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_hits.most_common():
            writer.writerow([ip, count])
        
        writer.writerow([])  # Empty row as separator
        
        # Write top endpoints
        writer.writerow(['=== Most Accessed Endpoints ==='])
        writer.writerow(['Endpoint', 'Access Count'])
        for endpoint, count in endpoints.most_common(5):
            writer.writerow([endpoint, count])
            
        writer.writerow([])
        
        # Write suspicious activity
        writer.writerow(['=== Suspicious Activity (Failed Logins) ==='])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious.items():
            writer.writerow([ip, count])

def print_analysis_results(ip_hits: Counter, endpoints: Counter, suspicious: Dict[str, int]) -> None:
    """Print analysis results to terminal."""
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
    for endpoint, count in endpoints.most_common(5):
        print(f"{endpoint:<40} {count}")

    print("\n3. Suspicious Activity (Failed Logins)")
    print("-" * 45)
    print("IP Address           Failed Login Count")
    print("-" * 45)
    for ip, count in suspicious.items():
        print(f"{ip:<20} {count}")

def main(filename: str = "sample.log") -> None:
    try:
        # Analyze log file
        ip_hits, endpoints, failed_logins = analyze_log(filename)
        
        # Filter suspicious activity (10 or more failed logins)
        suspicious = {ip: count for ip, count in failed_logins.items() if count >= 10}
        
        # Output results
        print_analysis_results(ip_hits, endpoints, suspicious)
        write_results_to_csv(ip_hits, endpoints, suspicious)
        
    except Exception as e:
        print(f"Error processing log file: {e}")

if __name__ == "__main__":
    main()
