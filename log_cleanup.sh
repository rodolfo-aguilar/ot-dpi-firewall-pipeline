#!/bin/bash

# --- CONFIGURATION ---
# Target log file (supports either your Mac project path or /var/log/ file)
LOG_FILE="$HOME/Documents/Projects/otcybersecurity/logs/dpi_firewall_violations.log"
ARCHIVE_DIR="$HOME/Documents/Projects/otcybersecurity/logs/archive"

# Size threshold in Kilobytes (10240 KB = 10 Megabytes)
SIZE_THRESHOLD=10240

# Ensure the archive directory exists before running
mkdir -p "$ARCHIVE_DIR"

# Check if the log file exists
if [ ! -f "$LOG_FILE" ]; then
    echo "[-] Error: Log file $LOG_FILE does not exist."
    exit 1
fi

# Get current file size in Kilobytes (works flawlessly on both macOS and Linux)
FILE_SIZE=$(du -k "$LOG_FILE" | cut -f1)

echo "[*] Current log file size: ${FILE_SIZE}KB (Threshold: ${SIZE_THRESHOLD}KB)"

# Check if file size exceeds our specified threshold
if [ "$FILE_SIZE" -gt "$SIZE_THRESHOLD" ]; then
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    ARCHIVE_FILE="$ARCHIVE_DIR/dpi_firewall_violations_$TIMESTAMP.log.gz"
    
    echo "[!] Log size exceeded limit. Archiving..."
    
    # 1. Compress the current log file directly into the archive folder
    gzip -c "$LOG_FILE" > "$ARCHIVE_FILE"
    
    # 2. Safely clear the active log file contents without deleting the file descriptor
    cat /dev/null > "$LOG_FILE"
    
    echo "[✓] Archive successfully saved to: $ARCHIVE_FILE"
    echo "[✓] Active firewall log cleared."
else
    echo "[✓] Log file size is within safe limits. No action required."
fi
