#!/bin/bash

if [ "$#" -ne 7 ]; then
    echo "Usage: $0 <code_directory> <file_directory> <standard> <MIMO> <config> <bandwidth> <MAC>"
    exit 1
fi

CODE_DIRECTORY=$1
FILE_DIRECTORY=$2
STANDARD=$3
MIMO=$4
CONFIG=$5
BW=$6
MAC=$7

# Absolute path to the Python script
PYTHON_SCRIPT="${CODE_DIRECTORY}/process_pcap.py"

python3 "$PYTHON_SCRIPT" "$FILE_DIRECTORY" "$STANDARD" "$MIMO" "$CONFIG" "$BW" "$MAC"

