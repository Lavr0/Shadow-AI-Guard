from mitmproxy import http
import database,requests,re,threading,json

database.init_db()
'''list of patterns that are considered vulnerable data'''
vulnerable_data = [
    r"AFM",
    r"ΑΦΜ",
    r"AMKA",
    r"sk-[a-zA-Z0-9]{20,}",
    r"Password",
    r"secret",
    r"classified",
    r"do not share",
    r"confidential",
    r"\b\d{9}\b",                                   
    r"\b(?:\d[ -]*?){13,16}\b",                       
    r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"        
]
LLM_DOMAINS = [
    "api.openai.com",
    "chatgpt.com",
    "api.anthropic.com",
    "claude.ai",
    "generativelanguage.googleapis.com",
    "api.deepseek.com",
    "chatgpt.com",
    "chatgpt.com",
    "gemini.google.com",
    "chat.deepseek.com"
]

def mask_sensitive_data(text):      # hides sensitive data,leaving only 4 last sensitive digits
    if not text or text=="None":
        return "None"
    
    if not any(char.isdigit() for char in text):
        return "[CONFIDENTIAL KEYWORD]"

    if len(text)>4:
        return "*" * (len(text) - 4) + text[-4:]
    return "****"
    
def extract_clean_text(raw_content):
    """Επιστρέφει ΜΟΝΟ το καθαρό κείμενο του χρήστη από έγκυρο JSON συνομιλίας. Αλλιώς None."""
    try:
        data = json.loads(raw_content)    #Προσπαθεί να μετατρέψει το ακατέργαστο σώμα του αιτήματος (raw_content) από απλό κείμενο σε λεξικό (dictionary) της Python, ελέγχοντας αν έχει έγκυρη δομή JSON
        if isinstance(data, dict) and "messages" in data and isinstance(data["messages"], list):    #Ελέγχει αν το JSON περιέχει τη λίστα "messages"
            last_msg = data["messages"][-1]                                 #Παίρνει το τελευταίο αντικείμενο της λίστας (-1), το οποίο αντιστοιχεί στο πιο πρόσφατο μήνυμα που μόλις έστειλε ο χρήστης
            parts = last_msg.get("content", {}).get("parts", [])            #Ακολουθεί την εσωτερική ιεραρχία του JSON του ChatGPT (messages->content->parts), όπου αποθηκεύεται το περιεχόμενο του μηνύματος. Η χρήση της μεθόδου .get() αποτρέπει τα σφάλματα (KeyError) αν κάποιο από αυτά τα κλειδιά λείπει
            text_parts = [p for p in parts if isinstance(p, str)]           #Φιλτράρει τα στοιχεία της λίστας parts και κρατάει μόνο όσα είναι καθαρό κείμενο (str), αγνοώντας τυχόν εικόνες ή συνημμένα αρχεία που μπορεί να βρίσκονται στην ίδια λίστα.
            if text_parts:
                return " ".join(text_parts)                                 #Ενώνει τα κομμάτια κειμένου σε μία ενιαία, καθαρή πρόταση και την επιστρέφει για να ελεγχθεί από τα Regex και το Ollama
    except Exception:
        pass
    
    # Αν ΔΕΝ είναι έγκυρο JSON με "messages" (π.χ. συμπιεσμένα bytes ή telemetry), το αγνοούμε!
    return None


def check_prompt_async(clean_text):
    try:
        
        prompt = (
            "Analyze the following text. Does it contain sensitive personal data (like names, phone numbers, "
            "IDs, passwords, or financial details) or confidential company secrets? "
            "Answer ONLY with 'YES' or 'NO'.\n\nText: " + clean_text
        )
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "phi3",
                "prompt": prompt,
                "stream": False,
                "keep_alive": -1,  # Κρατάει το μοντέλο μόνιμα φορτωμένο στη μνήμη για μηδενική καθυστέρηση
                "options": {
                    "temperature": 0.0,
                    "num_predict": 5     #είναι ένα όριο ταχύτητας (κόφτης) που λέει στο Ollama πόσες λέξεις/κομμάτια λέξεων (tokens) το μέγιστο επιτρέπεται να παράγει στην απάντησή του
                }
            },
            timeout=30  
        )
        result = response.json().get("response", "").strip().upper()
        print(f"--> [OLLAMA RAW RESPONSE]: {result}")
        return "YES" in result
        
    except Exception as e:
        print(f"Ollama check failed: {e}")
        return False

def request(flow: http.HTTPFlow):
    target_domain = flow.request.pretty_host
    
    # 1. Μόνο LLM domains
    if target_domain not in LLM_DOMAINS:
        return

    # 2. Μόνο POST requests
    if flow.request.method != "POST":
        return

    # 3. Αγνοούμε βοηθητικά endpoints (όπως το /prepare που έτρωγε το timeout!)
    path = flow.request.path
    if "/prepare" in path or "telemetry" in path or "sentinel" in path:
        return

    # 4. Ασφαλής ανάγνωση κειμένου (αποφεύγει το UnicodeDecodeError του gzip)
    content = flow.request.get_text(strict=False)
    if not content:
        return

    # 5. Εξάγουμε ΜΟΝΟ το μήνυμα του χρήστη. Αν είναι άσχετο JSON (π.χ. {"p": "..."}), φεύγουμε αμέσως!
    clean_text = extract_clean_text(content)
    if not clean_text or not clean_text.strip():
        return

    print(f"\n--> [REAL MESSAGE CAPTURED] Domain: {target_domain} | Text: {clean_text}")
    
    detected = False
    matched_info = "None"
    
    # Έλεγχος 1: Regex (πάνω στο καθαρό κείμενο πλέον!)
    for pattern in vulnerable_data:
        match = re.search(pattern, clean_text, re.IGNORECASE)
        if match:
            detected = True
            matched_info = match.group(0)
            break
            
    # Έλεγχος 2: Ollama AI (καλείται ΜΟΝΟ για το πραγματικό μήνυμα, χωρίς να μπουκώνει!)
    if not detected:
        if check_prompt_async(clean_text):
            detected = True
            matched_info = "Ollama Semantic Match (Contextual PII)"
            
    client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "127.0.0.1"    
    
    if detected:
        flow.response = http.Response.make(
            403,
            b"BLOCKED BY SHADOW AI GUARD: Sensitive data detected!",                             
            {"Content-Type": "text/plain"}
        )
        action = "blocked"
        matched_info = mask_sensitive_data(matched_info)
        print(f"[BLOCKED] 🚨 Sent 403 to client for domain {target_domain}")
    else:
        action = "allowed"
        matched_info = "None"  
        
    database.add_log(client_ip, target_domain, action, matched_info)