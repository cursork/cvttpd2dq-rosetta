FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc-dev curl xz-utils python3 ca-certificates libatomic1 \
    && rm -rf /var/lib/apt/lists/*

# Download Node.js 25
RUN curl -fsSL https://nodejs.org/dist/v25.0.0/node-v25.0.0-linux-x64.tar.xz | \
    tar -xJ -C /opt && \
    mv /opt/node-v25.0.0-linux-x64 /opt/node25

# Copy test files
COPY test.c patch.py /

# Build the C test
RUN gcc -O0 /test.c -o /test

# Patch Node.js
RUN python3 /patch.py /opt/node25/bin/node /opt/node25/bin/node-patched && \
    chmod +x /opt/node25/bin/node-patched

# Run all tests
CMD echo "=== Test C reproducer ===" && \
    /test; \
    echo && \
    echo "=== Unpatched Node 25 ===" && \
    /opt/node25/bin/node -e "console.log('0.25 =', 0.25, '| 1.5 =', 1.5)" && \
    echo && \
    echo "=== Patched Node 25 ===" && \
    /opt/node25/bin/node-patched -e "console.log('0.25 =', 0.25, '| 1.5 =', 1.5)"
