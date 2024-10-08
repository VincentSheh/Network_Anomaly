#!/bin/bash

while true; do
    # Run packet capture for 5 minutes
    # Duration for tcpdump to run on each interface
    duration=10

    # Get all the cali network interface name
    grepInterfaces=$(ip link show | grep -o 'cali[[:alnum:]]*')
    readarray -t netInterfaces <<< "$grepInterfaces"
    # Array to store pcap filenames
    pcap_files=()

        
    # Loop over each interface and start tcpdump in the background
    duration=10
    host_ip="192.168.50.30"
    # Insert the kubernetes IPs here
    excluded_ips=("10.96.0.1" "192.168.50.112" "192.168.50.228")
    filter_condition="host $host_ip"
    for ip in "${excluded_ips[@]}"; do
            filter_condition+=" and not host $ip"
    done    
    
    # for intf in "${netInterfaces[@]}"; do
    #     filename="${intf}_capture.pcap"
    #     pcap_files+=("$filename") # Add filename to array
    #     echo "Starting packet capture on $intf for $duration seconds"
    #     timeout "$duration" tcpdump -i "$intf" "$filter_condition" -w "$filename" &
    # done

    # # Wait for all tcpdump processes to finish
    # wait

    # # Merge pcap files into one using joincap
    # filename="capture_$(date +%Y%m%d%H%M%S).pcap"
    # joincap -w "$filename" "${pcap_files[@]}"
    # echo "Merged pcap files into $filename"

    timeout 10 tcpdump -i enp0s3 "$filter_condition" -w "capture.pcap"
    # Delete the oldest pcap file
    # Find all pcap files, sort them, and delete all but the two most recent
    # ls -1tr capture_*.pcap | head -n -2 | xargs -d '\n' rm -f --
    sleep 3
    # Run Go code to process the two latest pcap files
    # TODO: Obtain the IP of the Ingress Controller and perform pass it as arguments
    sudo /usr/local/go/bin/go run readpcap.go
    # ./packet_collector
    # Repeat indefinitely
    sleep 5
done
