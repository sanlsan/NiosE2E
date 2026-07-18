URL="https://raw.githubusercontent.com/sanlsan/NiosE2E/main/client.py"
FILE="client.py"
TEMP_FILE="client_new.py"

echo "[*] Checking for updates from GitHub..."

if command -v curl &> /dev/null; then
    curl -s -o "$TEMP_FILE" "$URL"
else
    wget -q -O "$TEMP_FILE" "$URL"
fi

if [ ! -f "$TEMP_FILE" ]; then
    echo "[!] Failed to download update. Checking local internet connection..."
else
    if [ ! -f "$FILE" ]; then
        mv "$TEMP_FILE" "$FILE"
        echo "[+] Client downloaded successfully."
    elif ! cmp -s "$FILE" "$TEMP_FILE"; then
        mv "$TEMP_FILE" "$FILE"
        echo "[+] Successfully updated to the latest version!"
    else
        rm "$TEMP_FILE"
        echo "[*] You already have the latest version."
    fi
fi

echo "[*] Checking dependencies..."
python3 -m pip install cryptography --break-system-packages >/dev/null 2>&1 || python3 -m pip install cryptography >/dev/null 2>&1

echo "[*] Starting NiosE2E..."
python3 "$FILE"