@python -c "from mitmproxy.tools.main import mitmdump; mitmdump()" --set confdir="C:\Users\mikem.mitmproxy" --set ssl_insecure=true -s shadow_proxy.py %* 
