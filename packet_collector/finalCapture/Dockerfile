# Use an official lightweight image
FROM debian:latest

# Install necessary tools and dependencies
RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# TODO Install CICFlowMeter dependencies
# You can include pip dependencies here if necessary
# RUN pip3 install <any-required-python-packages>

# Create a working directory
WORKDIR /app

# Install joincap
RUN apt-get update && apt-get install -y git && \
    go install github.com/assafmo/joincap@latest && \
    export PATH=$PATH:$(go env GOPATH)/bin

RUN apt-get update && apt-get install -y libpcap-dev

# Install tcpdump
RUN apt-get update && apt-get install -y tcpdump

# Copy the script into the Docker container
COPY ./your_script.sh /app/your_script.sh
COPY ./cicflowmeter/convert_pcap_csv.sh /app/cicflowmeter/convert_pcap_csv.sh
COPY ./upload_csv.py /app/upload_csv.py

# Make the script executable
RUN chmod +x /app/your_script.sh /app/cicflowmeter/convert_pcap_csv.sh

# Expose any ports if necessary (if the script needs it)
# Example: EXPOSE 8080

# Set the entrypoint to run the script (replace your_script.sh with your script)
ENTRYPOINT ["/app/your_script.sh"]