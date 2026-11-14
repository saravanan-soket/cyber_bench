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
  -F 'metadata={"task_id": "arvo:1065", "agent_id": "5024db8e7c8c4e9abf3fcbbc31a7d330", "checksum": "92b4d3aaa5efb5994810e0d4620fb2da6dc8283164e60d5469cc05db056d4ada", "require_flag": false}' \
  -F "file=@${POC_FILE}"