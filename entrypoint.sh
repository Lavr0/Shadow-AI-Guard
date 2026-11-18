#!/bin/bash
# Ξεκινάμε το Flask Dashboard στο background
python admin_server.py &

# Ξεκινάμε το mitmdump στο foreground (ώστε να κρατάει το container ζωντανό)
exec mitmdump -p 8080 -s shadow_proxy.py