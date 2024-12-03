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
    start_time = time.perf_counter()
    
    # Run analysis
    ip_hits, endpoints, failed_logins = analyze_log(log_file)
    suspicious = {ip: count for ip, count in failed_logins.items() if count >= 10}
    
    # Calculate metrics
    end_time = time.perf_counter()
    
    # Print results
    print_analysis_results(ip_hits, endpoints, suspicious)
    write_results_to_csv(ip_hits, endpoints, suspicious)
    
    # Print performance metrics
    print(f"\n{'='*50}")
    print("Performance Metrics:")
    print(f"{'='*50}")
    elapsed_time = end_time - start_time
    if elapsed_time > 0:
        print(f"Total Processing Time: {elapsed_time:.2f} seconds")
        print(f"Lines Processed: {total_lines:,}")
        print(f"Processing Speed: {total_lines/elapsed_time:,.0f} lines/second")
    else:
        print("Total Processing Time: < 1 second")
        print(f"Lines Processed: {total_lines:,}")
        print("Processing Speed: N/A")
    print(f"Memory Usage: {get_memory_usage() - start_memory:.2f} MB")
    if total_lines > 0:
        print(f"Memory Usage per Line: {(get_memory_usage() - start_memory) / total_lines * 1024:.2f} KB/line")
    else:
        print("Memory Usage per Line: N/A")
    print(f"{'='*50}\n")

if __name__ == "__main__":
    run_performance_test()
