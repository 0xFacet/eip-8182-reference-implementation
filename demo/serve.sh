#!/usr/bin/env bash
# Serve the EIP-8182 browser demo on the LAN so a phone can reach it.
#
# Usage:
#   bash demo/serve.sh            # serves on port 8182
#   PORT=8000 bash demo/serve.sh  # alternative port
#
# After it prints the URLs, open the one matching your Mac's LAN IP on your
# phone (must be on the same Wi-Fi). The local zkey is 26 MB so the first
# load takes ~3-10 seconds depending on Wi-Fi; subsequent runs are cached.
set -euo pipefail

PORT="${PORT:-8182}"
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Serving $DEMO_DIR on port $PORT"
echo
echo "On this Mac:    http://localhost:$PORT/"

# Print every non-loopback IPv4 address so phone access is obvious.
for IP in $(ifconfig | awk '/inet [0-9]/ && $2 != "127.0.0.1" {print $2}'); do
  echo "On your phone:  http://$IP:$PORT/"
done

echo
echo "Press Ctrl+C to stop."
echo

cd "$DEMO_DIR"
exec python3 -m http.server "$PORT"
