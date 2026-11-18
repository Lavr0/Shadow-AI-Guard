from mitmproxy import http
import database, requests, re, threading, json, base64
import urllib.parse

database.init_db()

# Λίστα με τα patterns ευαίσθητων δεδομένων (Regex)
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
    r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
    r"(?i)(?:key|secret|token|auth|password|passwd|pwd)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.]{16,64}['\"]?"     
]

# Υποστηριζόμενα LLM Domains (Web & APIs)
LLM_DOMAINS = [
    "api.openai.com",
    "chatgpt.com",
    "api.anthropic.com",
    "claude.ai",
    "generativelanguage.googleapis.com",
    "geminiweb-pa.clients6.google.com",
    "api.deepseek.com",
    "chat.deepseek.com",
    "gemini.google.com"
]

def mask_sensitive_data(text):
    if not text or text == "None":
        return "None"
    if not any(char.isdigit() for char in text):
        return "[CONFIDENTIAL KEYWORD]"
    if len(text) > 4:
        return "*" * (len(text) - 4) + text[-4:]
    return "****"

def utf_sequence(blob: bytes) -> str:
    text = blob.decode("utf-8", errors="ignore")
    chunk = re.findall(r"[^\x00-\x1f\x7f-\x9f]{3,}", text)
    return " ".join(chunk)

def unwrap_text(obj, found_texts):
    """Universal αναδρομικός αποσυσκευαστής για οποιοδήποτε JSON (ChatGPT, Claude, DeepSeek, Gemini)."""
    ignore_keys = {"id", "conversation_id", "parent_message_id", "message_id", "timezone", "model", "p", "token", "role", "finish_reason", "index", "metadata"}
    
    if isinstance(obj, str):
        s = obj.strip()
        # Αν το string είναι εμφωλευμένο JSON (όπως στο f.req του Gemini), το ανοίγουμε αναδρομικά
        try:
            parsed = json.loads(s)
            if isinstance(parsed, (dict, list)):
                unwrap_text(parsed, found_texts)
                return
        except Exception:
            pass
        
        # Κρατάμε καθαρούς αριθμούς (ΑΦΜ, τηλέφωνα, κάρτες) ή κανονικές φράσεις με κενά
        if re.fullmatch(r'\d{9,16}', s) or (" " in s and not s.startswith("http") and not re.search(r'\S{40,}', s)):
            found_texts.append(s)
            
    elif isinstance(obj, list):
        for item in obj:
            unwrap_text(item, found_texts)
            
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k not in ignore_keys:
                unwrap_text(v, found_texts)

def extract_clean_text(raw_content):
    """Εξάγει καθαρό κείμενο από οποιοδήποτε LLM αίτημα (JSON, URL-encoded, Gemini f.req κ.λπ.)."""
    if isinstance(raw_content, bytes):
        raw_content = raw_content.decode('utf-8', errors="ignore")
        
    found_texts = []

    # 1. Προσπάθεια ως standard JSON (ChatGPT, Claude, DeepSeek API/Web)
    try:
        data = json.loads(raw_content)
        unwrap_text(data, found_texts)
    except Exception:
        pass

    # 2. Προσπάθεια ως URL-encoded / Gemini payloads
    try:
        parsed = urllib.parse.parse_qs(raw_content)
        
        # Modern Gemini
        req_values = [
            val[0] for key, val in parsed.items()
            if key.startswith("req") and key.endswith("___data__") and val
        ]
        if req_values:
            for item in req_values:
                try:
                    decoded = base64.b64decode(item, validate=True)
                except Exception:
                    decoded = item.encode("utf-8", errors="ignore")
                found_texts.append(utf_sequence(decoded))
                
        # Legacy Gemini (f.req)
        if "f.req" in parsed:
            outer = json.loads(parsed["f.req"][0])
            unwrap_text(outer, found_texts)
            
    except Exception:
        pass

    if not found_texts:
        return None

    # Ενώνουμε τα μοναδικά κείμενα και κρατάμε τους τελευταίους 1500 χαρακτήρες για να μη χάνουμε το μήνυμα
    combined = " ".join(dict.fromkeys(found_texts))
    return combined[-1500:]

def check_prompt_async(clean_text):
    try:
        prompt = (
            "<|system|>\n"
            "You are ShadowGuard-AI, an aggressive and strict Data Loss Prevention (DLP) system. "
            "Your job is to protect corporate assets and prevent any leakage of sensitive information to AI. "
            "You must flag ANY text that mentions internal meetings, board decisions, financial plans, mergers, acquisitions, "
            "passwords, API keys, credentials, personal names, home addresses, or proprietary company information.\n<|end|>\n"
            "<|user|>\n"
            "Analyze the text below. Does it mention or discuss internal company matters, confidential meetings, "
            "financial/business strategies, credentials, personal identifiable information (PII), or restricted information?\n\n"
            f"Text: {clean_text}\n\n"
            "Reply with EXACTLY ONE WORD: 'YES' if it touches upon any of these, or 'NO' otherwise.\n<|end|>\n"
            "<|assistant|>\n"
        )
        response = requests.post(
            "http://host.docker.internal:11434/api/generate",
            json={
                "model": "phi3",
                "prompt": prompt,
                "stream": False,
                "keep_alive": -1,
                "options": {
                    "temperature": 0.0,
                    "num_predict": 5
                }
            },
            timeout=60  
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

    # 3. Αγνοούμε βοηθητικά endpoints
    path = flow.request.path
    if "/prepare" in path or "telemetry" in path or "sentinel" in path or "metrics" in path:
        return

    # 4. Ανάγνωση περιεχομένου
    content = flow.request.get_text(strict=False)
    if not content:
        return

    # 5. Καθολική εξαγωγή κειμένου για όλες τις πλατφόρμες
    clean_text = extract_clean_text(content)
    if not clean_text or not clean_text.strip():
        return

    print(f"\n--> [REAL MESSAGE CAPTURED] Domain: {target_domain} | Text: {clean_text}")
    
    detected = False
    matched_info = "None"
    
    # Έλεγχος 1: Regex
    for pattern in vulnerable_data:
        match = re.search(pattern, clean_text, re.IGNORECASE)
        if match:
            detected = Type = True # fixed bool assign
            detected = True
            matched_info = match.group(0)
            break
            
    # Έλεγχος 2: Ollama AI Semantic Check
    if not detected:
        if check_prompt_async(clean_text):
            detected = True
            matched_info = "Ollama Semantic Match (Contextual PII)"
            
    client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "127.0.0.1"   

    if detected:
        # Ενιαίο μήνυμα σφάλματος για όλα τα ΑΙ συστήματα
        error_message = (
            "🚨 [SHADOW AI GUARD]: Request Blocked! "
            "Sensitive or confidential corporate data was detected in your prompt. "
            "The transmission has been terminated for security compliance."
        )
        
        flow.response = http.Response.make(
            403,
            error_message.encode("utf-8"),                             
            {"Content-Type": "text/plain; charset=utf-8"}
        ) 
    
    if detected:
        flow.response = http.Response.make(
            403,
            b"BLOCKED BY SHADOW AI GUARD: Sensitive data detected!",
            {"Content-Type": "text/plain"}
        )
        action = "blocked"
        if matched_info == "Ollama Semantic Match (Contextual PII)":
            matched_info = "CONTEXTUAL PII LEAK"
        else:
            matched_info = mask_sensitive_data(matched_info)
        print(f"[BLOCKED] 🚨 Sent 403 to client for domain {target_domain}")
    else:
        action = "allowed"
        matched_info = "None"
        
    database.add_log(client_ip, target_domain, action, matched_info)