Set WshShell = CreateObject("WScript.Shell")

' 1. Ξεκινάει το Ollama στο background (χωρίς παράθυρο)
WshShell.Run "ollama serve", 0, False

' Αναμονή 3 δευτερόλεπτων για να σηκωθεί το Ollama
WScript.Sleep 3000

' 2. Ξεκινάει το Flask Dashboard στο background (χωρίς παράθυρο)
WshShell.Run "python admin_server.py", 0, False

' Αναμονή 2 δευτερόλεπτων για να σηκωθεί το Flask
WScript.Sleep 2000

' 3. Ξεκινάει το Mitmproxy στο background (χωρίς παράθυρο)
WshShell.Run "mitmdump -p 8080 -s shadow_proxy.py", 0, False

' Αναμονή 1 δευτερόλεπτο και άνοιγμα του browser
WScript.Sleep 1000
' 4. Άνοιγμα του Google Chrome απευθείας στο Dashboard
WshShell.Run "chrome http://localhost:5000", 0, False