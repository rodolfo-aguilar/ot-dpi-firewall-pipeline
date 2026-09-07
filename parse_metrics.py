import os
import sys
from collections import Counter
from datetime import datetime

# Absolute path to the original system-level log file definition
ORIGINAL_SYSTEM_LOG = "/Users/rodolfoaguilar/Documents/Projects/otcybersecurity/logs/dpi_firewall_violations.log"

def analyze_system_dpi_blocks():
    # Defensive Check: Verify the file exists before parsing
    if not os.path.exists(ORIGINAL_SYSTEM_LOG):
        print(f"[-] Error: Log file not found at {ORIGINAL_SYSTEM_LOG}")
        print("[*] Note: If you are running on macOS, you may need to use 'sudo python3' to see files in /var/log/")
        return

    print(f"[*] Extracting system-level DPI analytics from: {ORIGINAL_SYSTEM_LOG}")
    print("=" * 65)

    hourly_blocks = Counter()
    total_blocks = 0

    try:
        # Open and process the log file line by line
        with open(ORIGINAL_SYSTEM_LOG, 'r') as file:
            for line in file:
                # Check for the distinct block marker we used in the first script
                if "[❌ BLOCK]" in line:
                    total_blocks += 1
                    
                    try:
                        # Extract the timestamp prefix (e.g., 2026-08-10 21:04:15,123)
                        parts = line.split(" [")
                        timestamp_part = parts[0]
                        
                        # Strip milliseconds separating by the comma
                        time_clean = timestamp_part.split(",")[0]
                        
                        # Convert the log line string into a Python datetime object
                        dt = datetime.strptime(time_clean, "%Y-%m-%d %H:%M:%S")
                        
                        # Flatten minutes and seconds into a clean hour bucket string
                        hour_bucket = dt.strftime("%Y-%m-%d %H:00")
                        
                        # Increment the specific hour count
                        hourly_blocks[hour_bucket] += 1
                    except Exception:
                        # Skip lines with unexpected formatting anomalies gracefully
                        continue
    except PermissionError:
        print("[-] Permission Denied: Please run this script with 'sudo' to read from /var/log/")
        return

    print(f"[📊 FIREWALL TELEMETRY] Total Industrial Attack Actions Blocked: {total_blocks}")
    print("=" * 65)
    
    if total_blocks == 0:
        print("[✓] Zero policy violations detected in the system network log.")
        return

    print(f"{'Hour Window':<25} | {'Deflected Packets':<20}")
    print("-" * 65)
    
    # Render the metrics sorted oldest to newest chronologically
    for hour, count in sorted(hourly_blocks.items()):
        print(f"{hour:<25} | {count:<20} blocks")

if __name__ == "__main__":
    analyze_system_dpi_blocks()
