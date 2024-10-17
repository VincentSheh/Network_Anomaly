#!/bin/bash
usage() {
    echo "Usage: $0 -f filename"
    echo "  -f    specify the CSV filename"
    echo "  -h    display this help message"
    exit 1
}
#Default Configurations
duration=10
csvFolder="output"
device="enp0s3"
filter_condition="(host 192.168.50.12 || host 192.168.50.181)"

# Synchronization Variables
blocking_pid=""
# Lock_files
detection_lock_file="/tmp/detection_thread.lock"
block_lock_file="/tmp/block_thread.lock"


while getopts hf:i:c:d: flag
do
    case "${flag}" in
        h) usage;;
        f) csvFolder=${OPTARG};;
        i) host_ip=${OPTARG};;
        c) filter_condition=${OPTARG};;
        d) device=${OPTARG};;
    esac
done
echo $csvFolder
echo $filter_condition
# Function to handle cleanup on exit
cleanup() {
    echo "Caught SIGINT signal! Cleaning up..."
    pkill -P $$ # Kill all background processes started by this script
    exit 0
}

# Trap SIGINT (Ctrl+C)
trap cleanup SIGINT


# Function to start the detection thread in Python
start_detection_thread() {
    local pcap_file="$1"
    local csv_file="./cicflowmeter/$csvFolder/$(basename "$pcap_file" .pcap)_ISCX.csv"

    echo -e "\e[32mStarting detection thread for pcap file: $pcap_file\e[0m"

    {    # Convert the pcap to CSV using CICFlowMeter
    echo -e "\e[34mConverting pcap to CSV: $pcap_file\e[0m"
    ./cicflowmeter/convert_pcap_csv.sh "$pcap_file" "$csvFolder" > /dev/null 2>&1
    echo -e "\e[32mConversion to CSV completed: $csv_file\e[0m"
    sleep 5

    # Start the Python detection script
    echo -e "\e[32mStarting detection on CSV file: $csv_file\e[0m"
    python3 upload_csv.py -f "$csv_file" -s 1

    # sleep 50  # Simulate some delay for the detection process
    echo -e "\e[32mDetection Finished: Releasing Lock\e[0m"
    rm -f "$detection_lock_file"  # Remove the lock directory

    # If block_lock_file doesn't exist, perform the blocking operation
    if [[ ! -f "$block_lock_file" ]]; then
        touch "$block_lock_file"  # Acquire the lock for blocking
        perform_blocking &        # Perform the blocking in the background
        blocking_pid=$!           # Capture the PID of the blocking process
    else
        # If block_lock_file exists, terminate the previous blocking operation
        echo -e "\e[31mBlocking operation is already running. Terminating the previous one...\e[0m"
        if [[ -n "$blocking_pid" ]] && kill -0 "$blocking_pid" 2>/dev/null; then
            kill "$blocking_pid"
            wait "$blocking_pid" 2>/dev/null
            echo -e "\e[31mPrevious blocking operation terminated.\e[0m"
        fi
        sudo iptables -F
        # Start a new blocking operation
        touch "$block_lock_file"  # Re-acquire the lock for the new blocking operation
        perform_blocking &        # Start the new blocking operation in the background
        blocking_pid=$!           # Update the PID of the new blocking process
    fi
    } &
}
# Function to run tcpdump
run_tcpdump() {
    while true; do
        rm -f capture_*.pcap
        name="$(date +%Y%m%d%H%M%S)"
        filename="capture_$name.pcap"

        echo -e "\e[34mRunning tcpdump for $duration seconds...\e[0m"

        timeout "$duration" tcpdump -i "$device" "$filter_condition" -w "$filename" & wait

        echo "Pcap file created: $filename"

        # Start a detection thread if none is running
        if [[ ! -f "$detection_lock_file" ]]; then
            touch -f "$detection_lock_file"  
            echo -e "\e[32mNo detection currently running. Starting detection...\e[0m"
            start_detection_thread "$filename" &
        else
            echo -e "\e[31mDetection is already running, skipping new detection\e[0m"
        fi

        sleep 1
    done
}
# Function to perform the actual blocking
perform_blocking() {
    local block_duration=30
    local block_list_file="malicious_ip.txt"
    
    echo -e "\e[33mPerforming blocking operation...\e[0m"
    # Read the contents of the block list file into an array
    if [[ -f "$block_list_file" ]]; then
        mapfile -t ip_list < "$block_list_file"
        # Delete the file immediately after reading
        rm -f "$block_list_file"

        # Iterate over the list of IPs to block
        for ip_to_block in "${ip_list[@]}"; do
            # Start a background process for blocking each IP
            {
                echo -e "\e[33mBlocking $ip_to_block for $block_duration seconds\e[0m"
                
                # Use the RAW table to prevent connection tracking for the IP
                sudo iptables -t raw -A PREROUTING -s "$ip_to_block" -j NOTRACK
                sudo iptables -t raw -A PREROUTING -d "$ip_to_block" -j NOTRACK

                # Sleep for the block duration
                sleep "$block_duration"

                # Remove the NOTRACK rule after the block duration
                sudo iptables -t raw -D PREROUTING -s "$ip_to_block" -j NOTRACK
                sudo iptables -t raw -D PREROUTING -d "$ip_to_block" -j NOTRACK
                
                echo -e "\e[33mUnblocked $ip_to_block\e[0m"
            } &  # Run the blocking operation in the background
        done
        # Wait for all background blocking processes to finish
        wait
    else
        echo -e "\e[33mNo block list file found.\e[0m"
    fi
    rm -rf "$block_lock_file" #Release The Lock
    echo -e "\e[33mReleasing Block Lock\e[0m"
}


# Remove any Lock File from previous run
rm -r "$block_lock_file"
rm -r "$detection_lock_file"

# Start tcpdump and blocking functions in parallel
run_tcpdump &
tcpdump_pid=$!

# run_block_function &
# block_func_pid=$!

# Wait for the background processes to complete
wait $tcpdump_pid