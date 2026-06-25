#!/bin/bash
set -e

# Path to the SoftHSM token directory inside the container
TOKEN_DIR="/var/lib/softhsm/tokens"

# Check if the token directory is empty (meaning it's the first boot)
if [ -z "$(ls -A $TOKEN_DIR 2>/dev/null)" ]; then
    echo "First boot detected. Initializing SoftHSM token and generating RSA key..."

    # 1. Initialize the slot
    softhsm2-util --init-token --slot 0 --label "kbs-token" --pin 1234 --so-pin 1234

    # 2. Generate the RSA 2048 keypair inside the slot
    pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
                --login --pin 1234 \
                --keypairgen --key-type rsa:2048 \
                --label "kbs-key" --usage-decrypt

    echo "SoftHSM initialization complete."
else
    echo "Persistent SoftHSM tokens found. Skipping initialization."
fi

# Execute the main KBS process passed from the Dockerfile/command line
exec "$@"
