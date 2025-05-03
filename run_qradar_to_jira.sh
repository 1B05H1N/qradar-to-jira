#!/bin/bash

# Set the working directory to the script's location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Load environment variables
if [ -f .env ]; then
    source .env
else
    echo "Error: .env file not found in $SCRIPT_DIR"
    exit 1
fi

# Create log directory if it doesn't exist
LOG_DIR="/var/log/qradar_to_jira"
mkdir -p "$LOG_DIR"

# Set up log file with timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$LOG_DIR/qradar_to_jira_$TIMESTAMP.log"

# Run the script and log output
echo "Starting QRadar to Jira integration at $(date)" >> "$LOG_FILE"
python qradar_to_jira.py >> "$LOG_FILE" 2>&1
EXIT_CODE=$?

# Log completion status
if [ $EXIT_CODE -eq 0 ]; then
    echo "Script completed successfully at $(date)" >> "$LOG_FILE"
else
    echo "Script failed with exit code $EXIT_CODE at $(date)" >> "$LOG_FILE"
fi

# Clean up old log files (keep last 30 days)
find "$LOG_DIR" -name "qradar_to_jira_*.log" -mtime +30 -delete

exit $EXIT_CODE 