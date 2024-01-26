#!/bin/bash

while true; do
    # Run packet capture for 5 minutes
    filename="capture_$(date +%Y%m%d%H%M%S).pcap"
    tcpdump -w $filename -G 300 -W 1

    # Delete the oldest pcap file
    # Find all pcap files, sort them, and delete all but the two most recent

    ls -1tr capture_*.pcap | head -n -2 | xargs -d '\n' rm -f --
    
    # Run Go code to process the two latest pcap files
    go run yourgocode.go



    # Repeat indefinitely
    sleep 5
done
