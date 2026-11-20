# Shadow AI Guard

Τοπικό περιβάλλον ασφαλείας και καταγραφής κίνησης AI με **mitmproxy** (`shadow_proxy.py`), admin server/dashboard (`admin_server.py`), **PostgreSQL** (`postgres:15-alpine`) και έλεγχο prompts μέσω **Ollama**.

---

## Προαπαιτούμενα

- **Docker Desktop** (με ενεργό Docker Engine / Compose)
- **Git** (προαιρετικά, για λήψη/έκδοση κώδικα)
- **Ollama** εγκατεστημένο στο σύστημα (για έλεγχο/μπλοκάρισμα prompts μέσω τοπικού LLM)
- Browser (π.χ. Google Chrome) με εγκατεστημένη την επέκταση **ZeroOmega**

---

## 1. Κατέβασμα & Προετοιμασία Αρχείων

Τοποθετήστε το project σε καθαρή διαδρομή χωρίς περιττούς χαρακτήρες ή κενά (π.χ. `C:\shadow-ai-guard-test`).

### Line endings (`entrypoint.sh`) & αρχεία Git
Τα Linux containers απαιτούν **LF (`\n`)** line endings και μία γραμμή `#!/bin/bash` στην αρχή του `entrypoint.sh`. Διαφορετικά μπορεί να εμφανιστεί το σφάλμα:

```text
exec ./entrypoint.sh: no such file or directory
=============================================================================================================
=============================================================================================================
1. Εγκατάσταση Ollama (phi3)
Βεβαιωθείτε ότι το Ollama τρέχει και κατεβάστε το μοντέλο phi3 (η εντολή είναι ίδια σε Windows και Linux):

ollama pull phi3
ollama run phi3 "Reply with OK"
=============================================================================================================
2. Χτίσιμο & Εκκίνηση του Project σε Docker Container:

docker compose down --remove-orphans
docker compose up -d --build

Για να επιβεβαιώσετε ότι τρέχουν σωστά τα containers:

docker compose ps
=============================================================================================================
3. Εγκατάσταση Πιστοποιητικού

    α. Εγκατάσταση στα Windows
    Ανοίξτε τον φάκελο του project (π.χ. C:\shadow-ai-guard-test) και μπείτε στον φάκελο .mitmproxy.

    Κάντε διπλό κλικ στο αρχείο mitmproxy-ca-cert (τύπου .cer) και πατήστε Install Certificate....

    Επιλέξτε Local Machine -> Next -> Automatically select the certificate store based on the type of certificate -> Next -> Finish.

    Επιβεβαίωση: Εμφανίζεται μήνυμα ότι η εισαγωγή ολοκληρώθηκε με επιτυχία.

    β. Εισαγωγή στις ρυθμίσεις του Chrome (αν χρειαστεί)
    Στον Chrome, πληκτρολογήστε chrome://settings/certificates στη γραμμή διευθύνσεων.

    Μπείτε στην ενότητα «Εγκατεστημένα από εσάς» (ή Trusted Root Certification Authorities) και πατήστε Import / Εισαγωγή.

    Επιλέξτε το αρχείο mitmproxy-ca-cert.cer από τον φάκελο .mitmproxy του project.
=============================================================================================================
4. Ρύθμιση ZeroOmega

    α. Δημιουργία Proxy Profile
    Ανοίξτε τις ρυθμίσεις (Options) της επέκτασης ZeroOmega.

    Στην ενότητα Profiles (αριστερά), πατήστε + New profile..., δώστε ένα όνομα όπως Shadow AI Guard, επιλέξτε Proxy Profile και πατήστε Create.

    Επιβεβαίωση: Το προφίλ Shadow AI Guard εμφανίζεται στη λίστα προφίλ και ανοίγουν τα πεδία ρύθμισης proxy.

    β. Ρύθμιση διεύθυνσης, θύρας και Bypass List
    Στο προφίλ Shadow AI Guard, συμπληρώστε:

    Protocol / Scheme: HTTP

    Server / Host: 127.0.0.1

    Port: 8080

    Ελέγξτε τη Bypass List (αφήστε μόνο τοπικές διευθύνσεις όπως localhost ή 127.0.0.1 αν χρειάζεται και μην προσθέσετε chatgpt.com / openai.com).

    Πατήστε Apply changes.

    γ. Ενεργοποίηση του προφίλ
    Πατήστε αριστερό κλικ στο εικονίδιο του ZeroOmega πάνω δεξιά στον Chrome και επιλέξτε Shadow AI Guard (αντί για [Direct]).
=============================================================================================================
5. Επανεκκίνηση Browser & Δοκιμή

    Κλείστε εντελώς όλα τα παράθυρα του browser (και τυχόν διεργασίες στο παρασκήνιο) και ανοίξτε τον ξανά. Στη συνέχεια:

        - Μπείτε στο ChatGPT (με ενεργό το προφίλ Shadow AI Guard στο ZeroOmega) και στείλτε ένα prompt δοκιμής.

        -Ανοίξτε στον browser μια καρτέλα στο url -> http://127.0.0.1:5000

        - Ελέγξτε τα logs του container για να επιβεβαιώσετε ότι καταγράφεται και αξιολογείται/μπλοκάρεται η κίνηση: