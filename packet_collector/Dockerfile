# Start from a Go base image
FROM golang:latest

# Install tcpdump
RUN apt-get update && apt-get install -y tcpdump



# Set the working directory in the container
WORKDIR /app

# Copy the Go source files into the container
COPY . .

# Fetch any dependencies
RUN go mod tidy

# Install joincap
RUN apt-get update && apt-get install -y git && \
    go install github.com/assafmo/joincap@latest && \
    export PATH=$PATH:$(go env GOPATH)/bin

RUN apt-get update && apt-get install -y libpcap-dev

# Build the Go project
RUN go build .

# Copy the bash script into the container
COPY capture.sh .

# Make the script executable
RUN chmod +x capture.sh

# Command to run on container start
CMD ["./capture.sh", "-f", "test.csv"]
