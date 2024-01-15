# Use the official Golang image as a parent image
FROM golang:1.21

# Set the working directory
WORKDIR /app

# Install libpcap-dev
RUN apt-get update && apt-get install -y libpcap-dev

# Copy Go modules and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . ./

# Build the application
RUN CGO_ENABLED=1 go build -o /ids

# Command to run the executable
#ENTRYPOINT is used to pass command line argument
ENTRYPOINT ["/ids"] 
