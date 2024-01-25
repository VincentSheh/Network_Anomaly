#!/bin/bash

POD_NAME="<your_pod_name>"
NAMESPACE="<your_namespace>"
INTERFACE="<network_interface>"
CAPTURE_DURATION=60  # Duration for each capture session in seconds
FILE_PREFIX="capture"
i=0

while true; do
    FILENAME="${FILE_PREFIX}_${i}.pcap"
    
    # Start Ksniff and run it in the background
    kubectl sniff $POD_NAME -n $NAMESPACE -i $INTERFACE -o $FILENAME &
    SNIFF_PID=$!
    
    # Wait for the specified capture duration
    sleep $CAPTURE_DURATION
    
    # Stop the current Ksniff process
    kill $SNIFF_PID
    
    # Wait for a short period to ensure the pcap file is closed properly
    sleep 5
    
    # Increment the file index for the next capture
    i=$((i+1))
done
