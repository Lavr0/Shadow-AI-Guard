from mitmproxy import http
import database,requests,re

'''list of patterns that are considered vulnerable data'''
vulnerable_data = [r"AFM",r"ΑΦΜ",r"AMKA",r"sk-[a-zA-Z0-9]{20,}",r"Password",
r"secret",r"classified",r"do not share",r"confidential",r"\b\d{9}\b",
r"\b(?:\d[ -]*?){13,16}\b",r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
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

def data_hook(flow: http.HTTPFlow):

    content = flow.request.text
    if not content:
        return
    target_domain = flow.request.pretty_host
    if target_domain in LLM_DOMAINS:
        detected = False
        for pattern in vulnerable_data:
            if re.search(pattern,content):
                detected = True # vulnerable data found
                break
        if detected :
            flow.response = http.Response.make(403,
            b"BLOCKED BY SHADOW AI GUARD: Sensitive data detected!",                                   
            {"Content-Type": "text/plain"}
            )
            action = "blocked"
            mathced_info = "Sensitive Data"
        else:
            action = "allowed" # no sensitive data detected so the text can pass
            mathced_info = "None"  
            
#Μενει η αποστολή του log στον admin 2