#!/bin/bash
#!/bin/bash
mitmdump -s shadow_proxy.py --listen-port 8080 --ssl-insecure &
exec python admin_server.py