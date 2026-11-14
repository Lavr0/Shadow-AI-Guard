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

def mask_sensitive_data(text):      #hides sensitive data,leaving only 4 last sensitive digits
    if not text or text=="None":
        return "None"
    
    if not any(char.isdigit() for char in text):
        return "[CONFIDENTIAL KEYWORD]"

    if len(text)>4:
        return "*" * (len(text) - 4) + text[-4:]
    return "****"
    


def request(flow: http.HTTPFlow):

    content = flow.request.text
    if not content:
        return
    target_domain = flow.request.pretty_host
    if target_domain in LLM_DOMAINS:
        detected = False
        mathced_info = "None"
        for pattern in vulnerable_data:
            match = re.search(pattern, content)
            if match:
                detected = True # vulnerable data found
                matched_info = match.group(0) # keeping what we found
                break
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
            mathced_info = "None"  
        database.add_log(client_ip, target_domain, action, matched_info)    
