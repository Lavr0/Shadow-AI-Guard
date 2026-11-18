@echo off
cd /d "%~dp0"
echo ========================================================
echo Starting Shadow AI Guard Ecosystem...
echo ========================================================

:: 1. Ξεκινάει το Ollama
echo [1/3] Starting Ollama server...
start cmd /k "ollama serve"

:: Δίνουμε 3 δευτερόλεπτα να σηκωθεί το Ollama
timeout /t 3 >nul

:: 2. Ξεκινάει το Dashboard (admin_server.py)
echo [2/3] Starting Dashboard (admin_server.py)...
start cmd /k "python admin_server.py"

:: 3. Ξεκινάει το mitmproxy με το shadow_proxy.py
echo [3/3] Starting mitmproxy...
start cmd /k "C:\Users\lampr\AppData\Local\Python\pythoncore-3.15-64\Scripts\mitmdump.exe -s shadow_proxy.py --set ssl_insecure=true"

echo ========================================================
echo Όλες οι υπηρεσίες ξεκίνησαν!
echo ========================================================
pause