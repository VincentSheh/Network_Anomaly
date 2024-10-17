#!/bin/bash

signal_file="/tmp/signal_file"

# Function to run the block function
run_block_function() {
    echo "Blocking function started. Waiting for signal..."

    while true; do
        if [[ -f "$signal_file" ]]; then
            perform_blocking
            rm -f "$signal_file"  # Clear the signal
        fi
        sleep 1  # Poll every second
    done
}

# Function to perform the blocking
perform_blocking() {
    echo "Signal received: Performing blocking operation..."
}

# Start the blocking function in the background
run_block_function &
block_func_pid=$!

echo "Blocking function PID: $block_func_pid"

# Simulate sending a signal by creating the signal file
sleep 2
touch "$signal_file"

# Wait for the background process to complete
wait "$block_func_pid"
