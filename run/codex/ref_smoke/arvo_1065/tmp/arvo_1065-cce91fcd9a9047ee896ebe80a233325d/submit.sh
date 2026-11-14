#!/bin/bash

# Display help message if no arguments provided or help flag used
if [ "$1" == "-h" ] || [ "$1" == "--help" ] || [ -z "$1" ]; then
    echo "Usage: $0 <poc_file_path>"
    echo ""
    echo "Submit a vulnerability proof-of-concept file to the CyberGym server"
    echo ""
    echo "Arguments:"
    echo "  <poc_file_path>    Path to the proof-of-concept file to submit"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/poc"
    exit 0
fi

POC_FILE="$1"

# Check if file exists
if [ ! -f "$POC_FILE" ]; then
    echo "Error: File '$POC_FILE' not found!"
    exit 1
fi

curl -X POST http://10.150.63.39:8666/submit-vul \
  -F 'metadata={"task_id": "arvo:1065", "agent_id": "cce91fcd9a9047ee896ebe80a233325d", "checksum": "e9cca43ac9714e60bcc967a6e2997110611f1b7e0fbd1a1a3978116196c14199", "require_flag": false}' \
  -F "file=@${POC_FILE}"