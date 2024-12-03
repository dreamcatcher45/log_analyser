import time
import psutil
import os
from log_parser import analyze_log, print_analysis_results, write_results_to_csv

def get_memory_usage():
    """Get current memory usage in MB"""
    process = psutil.Process()
    return process.memory_info().rss / 1024 / 1024  # Convert to MB

def count_file_lines(filename):
    """Count total number of lines in file efficiently"""
    with open(filename, 'rb') as f:
        return sum(1 for _ in f)

def run_performance_test(log_file="sample.log"):
    print(f"\n{'='*50}")
    print("Starting Performance Test")
    print(f"{'='*50}")
    
    # Get initial memory
    start_memory = get_memory_usage()
    
    # Count lines in log file
    try:
        total_lines = count_file_lines(log_file)
        print(f"\nLog file contains {total_lines:,} lines")
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found!")
        return
    
    # Measure parsing performance
    print("\nParsing log file...")
    start_time = time.time()
    
    # Run analysis
    ip_hits, endpoints, failed_logins = analyze_log(log_file)
    suspicious = {ip: count for ip, count in failed_logins.items() if count >= 3}
    
    # Calculate metrics
    end_time = time.time()
    end_memory = get_memory_usage()
    
    # Print results
    print_analysis_results(ip_hits, endpoints, suspicious)
    write_results_to_csv(ip_hits, endpoints, suspicious)
    
    # Print performance metrics
    print(f"\n{'='*50}")
    print("Performance Metrics:")
    print(f"{'='*50}")
    print(f"Total Processing Time: {end_time - start_time:.2f} seconds")
    print(f"Lines Processed: {total_lines:,}")
    print(f"Processing Speed: {total_lines/(end_time - start_time):,.0f} lines/second")
    print(f"Memory Usage: {end_memory - start_memory:.2f} MB")
    print(f"Memory Usage per Line: {((end_memory - start_memory) / total_lines) * 1024:.2f} KB/line")
    print(f"{'='*50}\n")

if __name__ == "__main__":
    run_performance_test()
