# Start from a base image with Go installed. Use a version tag as needed
FROM golang:1.21

# Install tcpdump
RUN apt-get update && apt-get install -y tcpdump

# Set the working directory in the container
WORKDIR /app

# Copy the Go source code into the container
# Replace 'yourgocode.go' and any other necessary files with your actual file names
COPY . .

# Build your Go program (replace 'yourgocode.go' with your actual file)
RUN go build -o pcapReader .

# Create a bash script to run tcpdump and your Go code
RUN echo '#!/bin/bash\n\
while true; do\n\
    filename="capture_$(date +%Y%m%d%H%M%S).pcap"\n\
    tcpdump -w $filename -G 10 -W 1\n\
    ls -1tr capture_*.pcap | head -n -2 | xargs -d "\\n" rm -f --\n\
    ./pcapReader\n\
    sleep 5\n\
done' > run.sh

# Make the bash script executable
RUN chmod +x run.sh

# Run the script when the container launches
CMD ["./run.sh"]

# RUN CGO_ENABLED=0 GOOS=linux go build -o /docker-gs-ping\