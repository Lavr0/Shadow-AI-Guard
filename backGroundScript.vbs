Set WshShell = CreateObject("WScript.Shell")

' 1. runs OLlama in the background
WshShell.Run "ollama serve", 0, False

' 2. starts mitmproxy
WshShell.Run "python -m mitmproxy.tools.main -p 8080 -s shadow_proxy.py", 0, False

' 3. runs the dashboard in the background
WshShell.Run "python app.py", 0, False