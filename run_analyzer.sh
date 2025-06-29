#!/bin/bash
# This script runs the Python analyzer using the correct virtual environment.
# This file exists to make it easier to run the analyzer from the command line.
# Otherwise, you'd have to boot up the virtual environment to run it.

# Find the absolute path of the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

# Define the full paths to the virtual environment's Python and the main script
VENV_PYTHON="$SCRIPT_DIR/venv/bin/python"
MAIN_SCRIPT="$SCRIPT_DIR/analyze_traffic.py"

# --- Error Checking ---
# Check if the Python executable exists
if [ ! -f "$VENV_PYTHON" ]; then
    echo "Error: Python executable not found at $VENV_PYTHON"
    echo "Please ensure the virtual environment 'venv' exists in the script directory."
    exit 1
fi

# Check if a log file path was provided as an argument
if [ -z "$1" ]; then
  echo "Error: Please provide the path to the log file as an argument."
  echo "Usage: ./run_analyzer.sh /path/to/logfile"
  exit 1
fi
# --- End Error Checking ---

echo "🚀 Running analysis using the project's virtual environment..."

# Execute the python script with the correct interpreter, passing along
# all arguments given to this shell script (e.g., the log file path)
"$VENV_PYTHON" "$MAIN_SCRIPT" "$@"
