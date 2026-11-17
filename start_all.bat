@echo off
echo Εκκινηση ολων των υπηρεσιων του Shadow-AI-Guard...

:: 1. Ξεκινάει το Ollama σε ξεχωριστό παράθυρο
start "Ollama Service" cmd /k "ollama serve"

:: 2. Ξεκινάει ο Flask Server (admin_server.py) σε ξεχωριστό παράθυρο
start "Flask Dashboard" cmd /k "python admin_server.py"

:: 3. Ξεκινάει το Mitmproxy με το shadow_proxy.py σε ξεχωριστό παράθυρο
start "Mitmproxy Guard" cmd /k "python -m mitmproxy.tools.main -p 8080 -s shadow_proxy.py"

:: 4. Ανοίγει αυτόματα και το δικό σου .exe (Άλλαξε το "to_programa.exe" με το πραγματικό όνομα του αρχείου σου)
start "admin_server.py"

echo.
echo Ολα τα συστηματα ξεκινησαν επιτυχως!
pause