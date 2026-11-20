from mitmproxy import http
import database, requests, re, json, base64
import urllib.parse

# Αρχικοποιεί τη βάση δεδομένων (δημιουργεί πίνακες αν δεν υπάρχουν)
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
    r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"   ,
    r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b",

    # Anthropic (sk-ant-...)
    r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",

    # Google / Gemini API Keys (AIza...)
    r"\bAIza[0-9A-Za-z_-]{35}\b",

    # AWS Access Key ID (AKIA..., ASIA...)
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",

    # GitHub Tokens (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_)
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b",
    r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",

    # Stripe Live/Test Secret & Restricted Keys (sk_live_, sk_test_, rk_live_, rk_test_)
    r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b",

    # Slack Tokens (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-)
    r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",

    # Hugging Face Tokens (hf_...)
    r"\bhf_[A-Za-z0-9]{30,}\b",

    # Bearer Tokens & JWTs (eyJ...)
    r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b",
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",

    # Private Keys (PEM / SSH / RSA / EC)
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",

    # Γενικά assignments (api_key=..., secret_key: "...", token=...)
    r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{16,}['\"]?",

    #generic API key form
    r"(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|token|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{16,}['\"]?"
         
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

# Λέξεις-κλειδιά σε paths που αφορούν βοηθητικά/τηλεμετρικά αιτήματα και αγνοούνται
IGNORE_PATH_KEYWORDS = (
    "/prepare", "telemetry", "sentinel", "metrics",
    "title", "feedback", "bootstrap", "settings", "account"
)


def mask_sensitive_data(text):
    if not text or text == "None":
        return "None"
    if not any(char.isdigit() for char in text):
        return "[CONFIDENTIAL KEYWORD]"
    if len(text) > 4:
        return "*" * (len(text) - 4) + text[-4:]
    return "****"

def utf_sequence(blob: bytes) -> str:
    # Αποκωδικοποιεί τα bytes ως UTF-8 αγνοώντας άκυρα bytes
    text = blob.decode("utf-8", errors="ignore")
    # Κρατάει εκτυπώσιμα κομμάτια κειμένου μήκους τουλάχιστον 3 χαρακτήρων
    chunk = re.findall(r"[^\x00-\x1f\x7f-\x9f]{3,}", text)
    return " ".join(chunk)

def unwrap_text(obj, found_texts):
    # Κλειδιά metadata/IDs που συνήθως δεν περιέχουν το μήνυμα του χρήστη
    ignore_keys = {"id", "conversation_id", "parent_message_id", "message_id", "timezone", "model", "p", "token", "role", "finish_reason", "index", "metadata"}
    
    if isinstance(obj, str):
        s = obj.strip()
        # Αν το string είναι στην πραγματικότητα άλλο JSON (π.χ. στο f.req του Gemini), το ανοίγει ξανά
        try:
            parsed = json.loads(s)
            if isinstance(parsed, (dict, list)):
                unwrap_text(parsed, found_texts)
                return
        except Exception:
            pass
        
        # Κρατάει αριθμούς 9-16 ψηφίων ή προτάσεις/κείμενα με κενά (χωρίς URLs ή τεράστιες λέξεις >=40 chars)
        if re.fullmatch(r'\d{9,16}', s) or (" " in s and not s.startswith("http") and not re.search(r'\S{40,}', s)):
            found_texts.append(s)
            
    elif isinstance(obj, list):
        # Επισκέπτεται αναδρομικά κάθε στοιχείο της λίστας
        for item in obj:
            unwrap_text(item, found_texts)
            
    elif isinstance(obj, dict):
        # Επισκέπτεται αναδρομικά τις τιμές των κλειδιών που δεν είναι στη λίστα εξαίρεσης
        for k, v in obj.items():
            if k not in ignore_keys:
                unwrap_text(v, found_texts)

def repair_greek_mojibake(text: str) -> str:
    if not text:
        return text
    out = []
    for ch in text:
        # Αν ο χαρακτήρας είναι ήδη κανονικός ελληνικός, τον κρατάμε ως έχει
        if "\u0370" <= ch <= "\u03ff" or "\u1f00" <= ch <= "\u1fff":
            out.append(ch)
            continue
       # Προσπαθεί να ανακτήσει το αρχικό byte από CP437 ή Latin-1
        fixed = False
        for enc in ("cp437", "latin-1"):
            try:
                b = ch.encode(enc)
                # Κρατάμε raw bytes για να τα αποκωδικοποιήσουμε ανά ζεύγη UTF-8 παρακάτω
                out.append(b)
                fixed = True
                break
            except Exception:
                continue
        if not fixed:
            out.append(ch)

    # Συνένωσε διαδοχικά bytes και αποκωδικοποίησέ τα ως UTF-8
    result = []
    byte_buf = bytearray()

    def flush_bytes():
        if byte_buf:
            result.append(byte_buf.decode("utf-8", errors="replace"))
            byte_buf.clear()

    for item in out:
        if isinstance(item, bytes):
            byte_buf.extend(item)
        else:
            flush_bytes()
            result.append(item)
    flush_bytes()
    return "".join(result)

def extract_clean_text(raw_content):
    
    if isinstance(raw_content, bytes):
        raw_content = raw_content.decode('utf-8', errors="replace")
        
    found_texts = []

    # 1. Προσπάθεια ανάγνωσης ως τυπικό JSON
    try:
        data = json.loads(raw_content)
        if isinstance(data, dict):
            for key in ("prompt", "text", "message", "content", "query"):
                val = data.get(key)
                if isinstance(val, str) and val.strip():
                    found_texts.append(val.strip())
        unwrap_text(data, found_texts)
    except Exception:
        pass

    # 2. Προσπάθεια ανάγνωσης ως URL-encoded
    try:
        parsed = urllib.parse.parse_qs(raw_content)
        
       
        req_values = [
            val[0] for key, val in parsed.items()
            if key.startswith("req") and key.endswith("___data__") and val
        ]
        if req_values:
            for item in req_values:
                try:
                    decoded = base64.b64decode(item, validate=True)
                except Exception:
                    decoded = item.encode("utf-8", errors="replace")
                found_texts.append(utf_sequence(decoded))
                
        
        if "f.req" in parsed:
            outer = json.loads(parsed["f.req"][0])
            unwrap_text(outer, found_texts)
            
    except Exception:
        pass

    if not found_texts:
        return None

    # Αφαιρεί διπλότυπα διατηρώντας τη σειρά και διορθώνει τυχόν ελληνικό mojibake
    joined=" ".join(dict.fromkeys(found_texts))
    return repair_greek_mojibake(joined)

def check_prompt_async(clean_text):
    try:
        fixed_text = repair_greek_mojibake(clean_text)

        # Κόβει μακροσκελή κομμάτια τεκμηρίωσης/οδηγιών εργαλείων (π.χ. Claude Docs) που μπερδεύουν το μοντέλο
        noise_markers = [
            "Create a doc, or apply several operations",
            "Claude Docs Create one object",
            "Short snake_case identifier"
        ]
        cleaned_for_llm = fixed_text
        for marker in noise_markers:
            if marker in cleaned_for_llm:
                cleaned_for_llm = cleaned_for_llm.split(marker, 1)[0]
        # Περιορίζει το κείμενο στους πρώτους 1500 χαρακτήρες για ταχύτητα και συγκέντρωση
        target_text = cleaned_for_llm.strip()[:1500]
        print(f"\n[DEBUG OLLAMA INPUT] total={len(clean_text)} | head={target_text[:400]}")
        prompt = (
            "<|system|>\n"
            "You are ShadowGuard-AI, a strict and comprehensive bilingual (Greek and English) "
            "Data Loss Prevention (DLP) security classifier. Your job is to detect and block ANY prompt "
            "or text that could leak, expose, transmit, analyze, or compromise sensitive, confidential, "
            "internal, proprietary, financial, operational, or personally identifiable information (PII).\n\n"
            "You MUST output YES if the text contains, mentions, references, or asks to process/exfiltrate ANY of the following "
            "(in Greek, English, or mixed):\n"
            "1. Credentials & Secrets: passwords, passcodes, PINs, access codes, credentials (διαπιστευτήρια, κωδικοί πρόσβασης), "
            "API keys, secret tokens, private keys, SSH/TLS keys, admin keys (κλειδιά διαχειριστή), session tokens, connection strings.\n"
            "2. Internal Infrastructure & Access: internal hostnames, private IPs, VPN/server/database details, production/staging servers "
            "(production server, βάση παραγωγής, εσωτερικός server), firewall/network rules, internal URLs or admin panels.\n"
            "3. Confidential Business, Legal & Financial Data: unreleased financials, budgets, salaries, payroll, bonuses, IBANs, bank accounts, "
            "invoices, pricing/margins, contracts, NDAs, M&A/acquisitions/layoffs, trade secrets, internal memos or board decisions "
            "(μισθοδοσία, ισολογισμοί, συμβόλαια, εξαγορές, απολύσεις, εμπορικά μυστικά, απόρρητα έγγραφα).\n"
            "4. Personal Identifiable Information (PII): full names tied to sensitive context, emails, phone/mobile numbers, home/street addresses, "
            "ID/passport numbers, tax IDs (ΑΦΜ), social security numbers (ΑΜΚΑ), medical/health info, employee/customer records "
            "(προσωπικά δεδομένα, τηλέφωνα, διευθύνσεις, ΑΦΜ, ΑΜΚΑ, στοιχεία πελατών/εργαζομένων).\n"
            "5. Exfiltration / Leak Intent: sharing sensitive company/client/user data or asking to format, summarize, translate, "
            "script, or send confidential/restricted data externally.\n\n"
            "Output NO ONLY when the text is completely benign, generic, public, educational, or non-sensitive "
            "(e.g., general coding questions, public facts, generic brainstorming without company/personal/secret data).\n<|end|>\n"
            "<|user|>\n"
            "Examples:\n"
            "- 'Εδώ είναι απόρρητα διαπιστευτήρια πρόσβασης (Διαπιστευτήριο:2216245) και το κλειδί διαχειριστή για το production server μας που απαγορεύεται αυστηρά να διαρρεύσουν έξω από την εταιρεία.' -> YES\n"
            "- 'Ο κωδικός πρόσβασης για τη βάση δεδομένων παραγωγής είναι DB_Pass#9921 και το ΑΦΜ του πελάτη 123456789.' -> YES\n"
            "- 'Σου στέλνω τη λίστα μισθοδοσίας του τμήματος και τα IBAN των εργαζομένων για να βγάλεις μέσο όρο.' -> YES\n"
            "- 'Εσωτερικό memo: Συζητήσαμε στο διοικητικό συμβούλιο την εξαγορά της εταιρείας και τις επικείμενες απολύσεις.' -> YES\n"
            "- 'Πάρε τα στοιχεία πελατών και το τηλέφωνο 6981122334 στην οδό Πατησίων 45 και φτιάξε μου αναφορά.' -> YES\n"
            "- 'Here are our confidential access credentials (Credential:2216245) and admin key for our production server, strictly forbidden to leak outside the company.' -> YES\n"
            "- 'Our internal database schema for payroll includes EmployeeSalaries(emp_id, tax_id, monthly_gross, iban_account).' -> YES\n"
            "- 'Confidential board memo: Q4 acquisition talks and restructuring plans before public announcement.' -> YES\n"
            "- 'User credentials admin_user / SecretKey!2026 for staging_db at 10.0.4.15.' -> YES\n"
            "- 'Γράψε μου μια συνάρτηση σε Python που ταξινομεί μια λίστα με αριθμούς.' -> NO\n"
            "- 'Εξήγησέ μου με απλά λόγια πώς λειτουργεί το Docker Compose και το reverse proxy.' -> NO\n"
            "- 'Ποιες είναι οι βασικές διαφορές ανάμεσα σε SQL και NoSQL βάσεις δεδομένων;' -> NO\n"
            "- 'Write a python function to sort a list of numbers.' -> NO\n"
            "- 'Explain how HTTP status codes 401, 403, and 502 work in web servers.' -> NO\n\n"
            "Inspect the following text carefully:\n"
            f"{target_text}\n\n"
            "Respond with ONLY ONE WORD: YES or NO.\n<|end|>\n"
            "<|assistant|>\n"
        )
        # Καλεί το Ollama που τρέχει στον host υπολογιστή εκτός του Docker container
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
    
    # Μόνο LLM domains
    if target_domain not in LLM_DOMAINS:
        return

    # Μόνο POST requests
    if flow.request.method != "POST":
        return

    # Αγνοούμε βοηθητικά endpoints
    path = flow.request.path or ""
    path_lower = path.lower()
    if any(k in path_lower for k in IGNORE_PATH_KEYWORDS):
        return


    # Ανάγνωση περιεχομένου
    content = flow.request.get_text(strict=False)
    if not content:
        return

    # Καθολική εξαγωγή κειμένου για όλες τις πλατφόρμες
    clean_text = extract_clean_text(content)
    if not clean_text or not clean_text.strip():
        return

    print(f"\n--> [CHAT POST CAPTURED] Domain: {target_domain} | Path: {path} | Text: {clean_text[-300:]}")
    
    detected = False
    matched_info = "None"
    
    # Έλεγχος 1: Regex
    for pattern in vulnerable_data:
        match = re.search(pattern, clean_text, re.IGNORECASE)
        if match:
            detected = True # fixed bool assign
            matched_info = match.group(0)
            break
            
    # Έλεγχος 2: Ollama AI Semantic Check
    if not detected:
        if check_prompt_async(clean_text):
            detected = True
            matched_info = "Ollama Semantic Match (Contextual PII)"
            
    client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "127.0.0.1"    
    # Αν εντοπιστεί ευαίσθητο περιεχόμενο, επιστρέφει 403 και καταγράφει το περιστατικό
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
    # Καταγράφει το αποτέλεσμα (blocked/allowed) στη βάση δεδομένων
    database.add_log(client_ip, target_domain, action, matched_info)