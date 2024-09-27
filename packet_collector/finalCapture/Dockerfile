# Use an official lightweight image
FROM debian:latest

# Install necessary tools and dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        wget \
        net-tools \
        tcpdump \
        libpcap-dev \
        python3 \
        python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*        

# Install Java
ENV JAVA_VERSION=11
RUN curl -L -o openjdk.tar.gz \
        https://builds.openlogic.com/downloadJDK/openlogic-openjdk/11.0.11%2B9/openlogic-openjdk-11.0.11%2B9-linux-x64.tar.gz \
    && mkdir /opt/jdk \
    && tar -zxf openjdk.tar.gz -C /opt/jdk --strip-components=1 \
    && rm -rf openjdk.tar.gz \
    && ln -sf /opt/jdk/bin/java /usr/local/bin/java \
    && ln -sf /opt/jdk/bin/javac /usr/local/bin/javac \
    && ln -sf /opt/jdk/bin/jlink /usr/local/bin/jlink \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*    

ENV JAVA_HOME=/opt/jdk
ENV PATH=$JAVA_HOME/bin:$PATH

# Install Go
ENV GO_VERSION=1.18.3
RUN wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz
    

# Set Go environment variables
ENV PATH="/usr/local/go/bin:${PATH}"

# Install joincap
RUN go install github.com/assafmo/joincap@latest

# Create a working directory
RUN mkdir -p /app/cicflowmeter
WORKDIR /app

# Copy the necessary files into the Docker container
COPY . '/app'
VOLUME ["/app/packetCaptureVolume"]

# Make the scripts executable
RUN chmod +x /app/docker_capture.sh /app/cicflowmeter/convert_pcap_csv.sh

# Set the entrypoint to run the script
ENTRYPOINT ["/app/docker_capture.sh", "-f", "/home/vs/Desktop/packetCaptureVolume"]
