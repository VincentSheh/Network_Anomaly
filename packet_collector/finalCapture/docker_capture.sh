#!/bin/bash

#csv Filename
usage() {
    echo "Usage: $0 -f filename"
    echo "  -f    specify the CSV filename"
    echo "  -h    display this help message"
    exit 1
}

csvFolder="output"    
host_ip="192.168.50.30" #Ingress-nginx external IP
excluded_ips=("192.168.50.54" "192.168.50.228")

filter_condition="host $host_ip"
for ip in "${excluded_ips[@]}"; do
    # if [ -z "$filter_condition"]; then
    #     filter_condition+="not host $ip"
    # else
        filter_condition+=" and not host $ip"
    # fi
done    
filter_condition="host 192.168.50.12 and (host 192.168.50.211 || host 192.168.50.181)"
while getopts hfic: flag
do
    case "${flag}" in
        h) usage;;
        f) csvFolder=${OPTARG};;
        i) host_ip=${OPTARG};;
        c) filter_condition=${OPTARG}
    esac
done
csvFolder=$(pwd)/${csvFolder}
echo $csvFolder
# Function to handle cleanup on exit
cleanup() {
    echo "Caught SIGINT signal! Cleaning up..."
    # Add any cleanup tasks here
    exit 0
}

# Trap SIGINT (Ctrl+C)
trap cleanup SIGINT
 
while true; do #TODO: Change this to a list of duration
    local_IDS_state=0
    iter_count=0
    duration=10
    # Get all the cali network interface name
    # grepInterfaces=$(ip link show | grep -o 'cali[[:alnum:]]*')
    # readarray -t netInterfaces <<< "$grepInterfaces"
    # Array to store pcap filenames
    pcap_files=()

        
    # Loop over each interface and start tcpdump in the background
    # host_ip="172.16.189.72" #Ingress-nginx
    # host_ip="172.16.189.71" #Metallb
    # Insert the kubernetes IPs here
    # excluded_ips=("10.96.0.1" "172.16.189.73" "172.16.166.128" "172.16.235.129" "192.168.50.228")
    # excluded_ips=("10.96.0.1" "172.16.189.73" "172.16.166.128" "172.16.235.129")

    # filter_condition="host 192.168.50.12 and host 192.168.50.181"

    # for intf in "${netInterfaces[@]}"; do
    #     filename="${intf}_capture.pcap"
    #     pcap_files+=("$filename") # Add filename to array
    #     echo "Starting packet capture on $intf for $duration seconds"
    #     timeout "$duration" tcpdump -i "$intf" "$filter_condition" -w "$filename" &
    # done

    # ? Wait for all tcpdump processes to finish
    # wait

    # # Merge pcap files into one using joincap
    # filename="capture_$(date +%Y%m%d%H%M%S).pcap"
    # joincap -w "$filename" "${pcap_files[@]}"
    # echo "Merged pcap files into $filename"

    # Delete previous pcap files
    rm -f capture_*.pcap
    name="$(date +%Y%m%d%H%M%S)"
    filename="capture_$name.pcap"
    timeout "$duration" tcpdump -i enp0s3 "$filter_condition" -w "$filename"
    wait
    echo "Pcap files created $filename"

    # TODO: Obtain the IP of the Ingress Controller and perform pass it as arguments
    # ? Using CICFlowMeter
    ./cicflowmeter/convert_pcap_csv.sh "$filename" "$csvFolder"


    # sudo /home/vs/miniconda3/bin/python upload_csv.py "./cicflowmeter/$csvFolder/merged_${name}_ISCX.csv"

    # #? Update the State Machine
    # if ["$iter_count" -eq 20]; then
    #     local_IDS_state=1
    # fi
    # #TODO: Get QoE Metric from QoE Analyzer and decide change of state
done






# while true; do

#     # Run packet capture for 5 minutes
#     # Duration for tcpdump to run on each interface
#     duration=200
#     # duration=10

#     # Get all the cali network interface name
#     # grepInterfaces=$(ip link show | grep -o 'cali[[:alnum:]]*')
#     # readarray -t netInterfaces <<< "$grepInterfaces"
#     # Array to store pcap filenames
#     pcap_files=()

        
#     # Loop over each interface and start tcpdump in the background
#     # host_ip="172.16.189.72" #Ingress-nginx
#     # host_ip="172.16.189.71" #Metallb
#     host_ip="192.168.50.30" #Ingress-nginx external IP
#     # Insert the kubernetes IPs here
#     # excluded_ips=("10.96.0.1" "172.16.189.73" "172.16.166.128" "172.16.235.129" "192.168.50.228")
#     # excluded_ips=("10.96.0.1" "172.16.189.73" "172.16.166.128" "172.16.235.129")
#     excluded_ips=("192.168.50.112" "192.168.50.228")

#     filter_condition="host $host_ip"
#     for ip in "${excluded_ips[@]}"; do
#         # if [ -z "$filter_condition"]; then
#         #     filter_condition+="not host $ip"
#         # else
#             filter_condition+=" and not host $ip"
#         # fi
#     done    
#     # filter_condition="host 192.168.50.12 and (host 192.168.50.211 || host 192.168.50.181)"
#     filter_condition="host 192.168.50.12 and host 192.168.50.181"

#     # for intf in "${netInterfaces[@]}"; do
#     #     filename="${intf}_capture.pcap"
#     #     pcap_files+=("$filename") # Add filename to array
#     #     echo "Starting packet capture on $intf for $duration seconds"
#     #     timeout "$duration" tcpdump -i "$intf" "$filter_condition" -w "$filename" &
#     # done

#     # # Wait for all tcpdump processes to finish
#     # wait

#     # # Merge pcap files into one using joincap
#     # filename="capture_$(date +%Y%m%d%H%M%S).pcap"
#     # joincap -w "$filename" "${pcap_files[@]}"
#     # echo "Merged pcap files into $filename"
#     name="$(date +%Y%m%d%H%M%S)"
#     filename="capture_$name.pcap"
#     timeout "$duration" tcpdump -i wlo1 "$filter_condition" -w "$filename"
#     wait
#     echo "Pcap files created $filename"



#     # Delete the oldest pcap file
#     # Find all pcap files, sort them, and delete all but the two most recent
#     ls -1tr capture_*.pcap | head -n -1 | xargs -d '\n' rm -f --
#     #TODOOO: Merge the 2 pcap file into one and go run . on the merged file
#     filelist=()
#     for file in capture_*; do
#         if [ -e "$file" ]; then # Check if the file exists
#             filelist+=("$file")
#             echo "$file"
#         fi
#     done
#     echo "Reading ${filelist[@]} \n"
#     merged_name="merged_${name}.pcap"
#     joincap -w "$merged_name" "${filelist[@]}"


#     #Concatenate with cumalated pcap file
#     # $
#     # mv temp_cumulated.pcap cumulated.pcap

#     # Run Go code to process the two latest pcap files
#     # TODO: Obtain the IP of the Ingress Controller and perform pass it as arguments
#     # sudo /usr/local/go/bin/go run .
#     # ? Using Go to convert pcap to csv
#     # sudo go run . --filename=$csvFilename
#     # ./packet_collector --filename test.csv
#     # ./packet_collector
#     # ? Using CICFlowMeter
#     ./cicflowmeter/convert_pcap_csv.sh "$merged_name" "$csvFolder"
#     # Repeat indefinitely
#     # sleep 5
#     # ! Merge the merged_*.pcap files
#     mergefilelist=()
#     for file in merged_*; do
#         if [ -e "$file" ]; then # Check if the file exists
#             mergefilelist+=("$file")
#             echo "$file"
#         fi
#     done  
#     joincap -w "cumulated.pcap" "${mergefilelist[@]}"  
#     ls -1tr merged_*.pcap | xargs -d '\n' rm -f --    

#     # TODO: Run python upload_csv -f {$csv_file}
#     # sudo /home/vs/miniconda3/bin/python upload_csv.py "./cicflowmeter/$csvFolder/merged_${name}_ISCX.csv"
# done




# while true; do

#     # Run packet capture for 5 minutes
#     # Duration for tcpdump to run on each interface
#     duration=200
#     # duration=10

#     # Get all the cali network interface name
#     # grepInterfaces=$(ip link show | grep -o 'cali[[:alnum:]]*')
#     # readarray -t netInterfaces <<< "$grepInterfaces"
#     # Array to store pcap filenames
#     pcap_files=()

        
#     # Loop over each interface and start tcpdump in the background
#     # host_ip="172.16.189.72" #Ingress-nginx
#     # host_ip="172.16.189.71" #Metallb
#     host_ip="192.168.50.30" #Ingress-nginx external IP
#     # Insert the kubernetes IPs here
#     # excluded_ips=("10.96.0.1" "172.16.189.73" "172.16.166.128" "172.16.235.129" "192.168.50.228")
#     # excluded_ips=("10.96.0.1" "172.16.189.73" "172.16.166.128" "172.16.235.129")
#     excluded_ips=("192.168.50.112" "192.168.50.228")

#     filter_condition="host $host_ip"
#     for ip in "${excluded_ips[@]}"; do
#         # if [ -z "$filter_condition"]; then
#         #     filter_condition+="not host $ip"
#         # else
#             filter_condition+=" and not host $ip"
#         # fi
#     done    
#     # filter_condition="host 192.168.50.12 and (host 192.168.50.211 || host 192.168.50.181)"
#     filter_condition="host 192.168.50.12 and host 192.168.50.181"

#     # for intf in "${netInterfaces[@]}"; do
#     #     filename="${intf}_capture.pcap"
#     #     pcap_files+=("$filename") # Add filename to array
#     #     echo "Starting packet capture on $intf for $duration seconds"
#     #     timeout "$duration" tcpdump -i "$intf" "$filter_condition" -w "$filename" &
#     # done

#     # # Wait for all tcpdump processes to finish
#     # wait

#     # # Merge pcap files into one using joincap
#     # filename="capture_$(date +%Y%m%d%H%M%S).pcap"
#     # joincap -w "$filename" "${pcap_files[@]}"
#     # echo "Merged pcap files into $filename"
#     name="$(date +%Y%m%d%H%M%S)"
#     filename="capture_$name.pcap"
#     timeout "$duration" tcpdump -i wlo1 "$filter_condition" -w "$filename"
#     wait
#     echo "Pcap files created $filename"



#     # Delete the oldest pcap file
#     # Find all pcap files, sort them, and delete all but the two most recent
#     ls -1tr capture_*.pcap | head -n -1 | xargs -d '\n' rm -f --
#     #TODOOO: Merge the 2 pcap file into one and go run . on the merged file
#     filelist=()
#     for file in capture_*; do
#         if [ -e "$file" ]; then # Check if the file exists
#             filelist+=("$file")
#             echo "$file"
#         fi
#     done
#     echo "Reading ${filelist[@]} \n"
#     merged_name="merged_${name}.pcap"
#     joincap -w "$merged_name" "${filelist[@]}"


#     #Concatenate with cumalated pcap file
#     # $
#     # mv temp_cumulated.pcap cumulated.pcap

#     # Run Go code to process the two latest pcap files
#     # TODO: Obtain the IP of the Ingress Controller and perform pass it as arguments
#     # sudo /usr/local/go/bin/go run .
#     # ? Using Go to convert pcap to csv
#     # sudo go run . --filename=$csvFilename
#     # ./packet_collector --filename test.csv
#     # ./packet_collector
#     # ? Using CICFlowMeter
#     ./cicflowmeter/convert_pcap_csv.sh "$merged_name" "$csvFolder"
#     # Repeat indefinitely
#     # sleep 5
#     # ! Merge the merged_*.pcap files
#     mergefilelist=()
#     for file in merged_*; do
#         if [ -e "$file" ]; then # Check if the file exists
#             mergefilelist+=("$file")
#             echo "$file"
#         fi
#     done  
#     joincap -w "cumulated.pcap" "${mergefilelist[@]}"  
#     ls -1tr merged_*.pcap | xargs -d '\n' rm -f --    

#     # TODO: Run python upload_csv -f {$csv_file}
#     # sudo /home/vs/miniconda3/bin/python upload_csv.py "./cicflowmeter/$csvFolder/merged_${name}_ISCX.csv"
# done
