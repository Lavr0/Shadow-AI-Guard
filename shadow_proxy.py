from mitmproxy import http
import database,requests,re

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
    
def ai_scan(text_to_check):
    try:
        '''Sets what the LLM should check for'''
        prompt = (
            "Analyze the following text. Does it contain sensitive personal data (like IDs, phone numbers, "
            "passwords, or financial details) or confidential company secrets that should not be shared publicly? "
            "Answer ONLY with 'YES' or 'NO'.\n\nText: " + text_to_check
        )
        response = requests.post(
            "http://localhost:11434/api/generate",
            json = {
                "model": "phi3",
                "prompt": prompt,
                "stream": False
            },
            timeout = 15 # Για διαχειρηση της κίνησης
        )
        result = response.json().get("response", "").strip().upper()
        print(f"--> [OLLAMA RAW RESPONSE]: {result}")
        return "YES" in result
    except Exception as e:
        print(f"Ollama check failed: {e}")
        return False



def request(flow: http.HTTPFlow):
    print(f"--> DOMAIN: {flow.request.pretty_host} | CONTENT: {flow.request.text}") # <-- Πρόσθεσε αυτό εδώ
    content = flow.request.text
    if not content:
        return
    target_domain = flow.request.pretty_host
    if target_domain in LLM_DOMAINS:
        detected = False
        matched_info = "None"
        for pattern in vulnerable_data:
            match = re.search(pattern, content)
            if match:
                detected = True # vulnerable data found
                matched_info = match.group(0) # keeping what we found
                break
        if not detected:
            if ai_scan(content):
                detected = True
                matched_info = "Ollama Semantic Match (Contextual PII)"
        # keeping ip
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "127.0.0.1"    
        if detected :
            flow.response = http.Response.make(403,
            b"BLOCKED BY SHADOW AI GUARD: Sensitive data detected!",                                   
            {"Content-Type": "text/plain"}
            )
            action = "blocked"
            matched_info = mask_sensitive_data(matched_info)
        else:
            action = "allowed" # no sensitive data detected so the text can pass
            matched_info = "None"  
        database.add_log(client_ip, target_domain, action, matched_info)    
 