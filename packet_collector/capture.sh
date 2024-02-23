#!/bin/bash

#csv Filename
usage() {
    echo "Usage: $0 -f filename"
    echo "  -f    specify the CSV filename"
    echo "  -h    display this help message"
    exit 1
}

csvFilename="output.csv"    
while getopts hf: flag
do
    case "${flag}" in
        h) usage;;
        f) csvFilename=${OPTARG};;
    esac
done
echo $csvFilename

while true; do

    # Run packet capture for 5 minutes
    # Duration for tcpdump to run on each interface
    duration=30

    # Get all the cali network interface name
    grepInterfaces=$(ip link show | grep -o 'cali[[:alnum:]]*')
    readarray -t netInterfaces <<< "$grepInterfaces"
    # Array to store pcap filenames
    pcap_files=()

        
    # Loop over each interface and start tcpdump in the background
    duration=10
    # host_ip="172.16.189.72" #Ingress-nginx
    # host_ip="172.16.189.71" #Metallb
    host_ip="192.168.50.30" #Ingress-nginx external IP
    # Insert the kubernetes IPs here
    # excluded_ips=("10.96.0.1" "172.16.189.73" "172.16.166.128" "172.16.235.129" "192.168.50.228")
    # excluded_ips=("10.96.0.1" "172.16.189.73" "172.16.166.128" "172.16.235.129")
    excluded_ips=("192.168.50.112" "192.168.50.228")

    filter_condition="host $host_ip"
    for ip in "${excluded_ips[@]}"; do
        # if [ -z "$filter_condition"]; then
        #     filter_condition+="not host $ip"
        # else
            filter_condition+=" and not host $ip"
        # fi
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

    filename="capture_$(date +%Y%m%d%H%M%S).pcap"
    timeout "$duration" tcpdump -i enp0s3 "$filter_condition" -w "$filename" &
    wait
    echo "Pcap files created $filename"



    # Delete the oldest pcap file
    # Find all pcap files, sort them, and delete all but the two most recent
    ls -1tr capture_*.pcap | head -n -2 | xargs -d '\n' rm -f --
    #TODOOO: Merge the 2 pcap file into one and go run . on the merged file
    filelist=()
    for file in capture_*; do
        if [ -e "$file" ]; then # Check if the file exists
            filelist+=("$file")
        fi
    done
    echo "Reading $filelist \n"
    joincap -w "merged.pcap" "${pcap_files[@]}"

    # Run Go code to process the two latest pcap files
    # TODO: Obtain the IP of the Ingress Controller and perform pass it as arguments
    # sudo /usr/local/go/bin/go run .
    sudo /usr/local/go/bin/go run . --filename=$csvFilename
    # ./packet_collector
    # Repeat indefinitely
    # sleep 5
done
