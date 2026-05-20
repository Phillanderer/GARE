FROM eclipse-temurin:21-jdk-jammy

# Install Python and dependencies
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    wget \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra
# To upgrade: bump GHIDRA_VERSION + GHIDRA_BUILD_DATE to match the NSA release
# filename (e.g. ghidra_12.1_PUBLIC_20260513.zip → VERSION=12.1, DATE=20260513).
ARG GHIDRA_VERSION=12.1
ARG GHIDRA_BUILD_DATE=20260513
ARG GHIDRA_RELEASE_NAME=Ghidra_${GHIDRA_VERSION}_build
ARG GHIDRA_ZIP=ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD_DATE}.zip

WORKDIR /opt
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/${GHIDRA_RELEASE_NAME}/${GHIDRA_ZIP} && \
    unzip -q ${GHIDRA_ZIP} && \
    rm ${GHIDRA_ZIP} && \
    mv ghidra_${GHIDRA_VERSION}_PUBLIC ghidra

ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV PATH="${GHIDRA_INSTALL_DIR}/support:${PATH}"

# Create app directory
WORKDIR /app

# Set Python path to include /app for src imports
ENV PYTHONPATH=/app:$PYTHONPATH

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# PyGhidra will auto-detect Ghidra from GHIDRA_INSTALL_DIR environment variable
# No additional installation needed

# Copy all application code
COPY src/ ./src/

# Copy Ghidra scripts to worker scripts directory for PyGhidra access
RUN mkdir -p /app/src/services/worker/scripts && cp -r src/scripts/ghidra_scripts/* /app/src/services/worker/scripts/

# Create data directory
RUN mkdir -p /app/data

# Expose API port
EXPOSE 8000

# Run the main API server
CMD ["python3", "-m", "src.routes.main"]
