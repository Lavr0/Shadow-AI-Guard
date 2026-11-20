# Shadow AI Guard

Τοπικό περιβάλλον ασφαλείας και καταγραφής κίνησης AI με **mitmproxy** (`shadow_proxy.py`), admin server/dashboard (`admin_server.py`), **PostgreSQL** (`postgres:15-alpine`) και έλεγχο prompts μέσω **Ollama**.

---

## Προαπαιτούμενα

- **Docker Desktop** (με ενεργό Docker Engine / Compose)
- **Git** (προαιρετικά, για λήψη/έκδοση κώδικα)
- **Ollama** εγκατεστημένο στο σύστημα (αν χρησιμοποιείται έλεγχος/μπλοκάρισμα prompts μέσω τοπικού LLM)
- Browser (π.χ. Google Chrome) με εγκατεστημένη την επέκταση **ZeroOmega**

---

## 1. Κατέβασμα & Προετοιμασία Αρχείων

Τοποθέτηστε το project σε καθαρή διαδρομή χωρίς περιττούς χαρακτήρες/κενά (π.χ. `C:\shadow-ai-guard-test`).

### Σημαντικό για Windows (`entrypoint.sh` & line endings)
Τα Linux containers απαιτούν **LF (`\n`)** line endings και μία γραμμή `#!/bin/bash` στην αρχή του `entrypoint.sh`. Διαφορετικά μπορεί να εμφανιστεί το σφάλμα:

```text
exec ./entrypoint.sh: no such file or directory

### Εγκατάσταση OLlama phi3
Τρέξτε την εντολή
    ollama pull phi3
και την εντολή
    ollama run phi3 "Reply with OK"
για να βεβαιωθείτε ότι το OLlama ξεκίνησε κανονικά


## 2.Χτίστιμο του project σε Docker Container
    Σε ένα τερματικό μέσα στον φάκελο του project γράψτε την παρακάτω εντολή
        docker compose up -d --build

## 3.Εγκατάσταση Πιστοποιητικού

    α.1.Εγκαταστήστε το mitmproxy-ca-cert.cer στα.Ανοίξτε τον φάκελο του project (π.χ. C:\shadow-ai-guard-test), κάντε διπλό κλικ στον φάκελο .mitmproxy και κάντε διπλό κλίκο στο αρχείο mitmproxy-ca-cert(τύπου .cer) και πατήστε Install Certificate.... Επιλέξτε Local Machine -> Next -> Automatically select the certificate store based on the type of certificate -> Next -> Finish.Verification: Εμφανίζεται μήνυμα ότι η εισαγωγή ολοκληρώθηκε με επιτυχία.

    b.Περάστε το και στις ρυθμίσεις του Chrome.Στον Chrome, γράψτε chrome://settings/certificates,μπείτε στην ενότητα "Εγκατεστημένα απο εσάς" και πατήστε import ή εισαγωγή
    και επιλέξτε το πιστοποιητικό απο τον φάκελο του project (.mitmporxy)

## 4.ZeroOmega setup

    α.Στην ενότητα Profiles (αριστερά), πάτηστε + New profile..., δώστε ένα όνομα όπως Shadow AI Guard, επίλεξτε Proxy Profile και πατήστε Create.
    Verification: Το προφίλ Shadow AI Guard εμφανίζεται στη λίστα προφίλ και ανοίγουν τα πεδία ρύθμισης proxy.

    β.Ρύθμιστε διεύθυνση, θύρα και Bypass List:1 λεπτό.Στο προφίλ Shadow AI Guard:Protocol / Scheme: HTTP (ή άφησε 127.0.0.1 με θύρα 8080 για HTTP/HTTPS proxy)Server / Host: 127.0.0.1Port: 8080Έλεγξτε τη Bypass List (π.χ. άφηστε εκεί μόνο τοπικές διευθύνσεις όπως localhost ή 127.0.0.1 αν χρειάζεται, και μην βάλετε μέσα chatgpt.com / openai.com). Έπειτα πατήστε Apply changes.Verification: Τα πεδία δείχνουν 127.0.0.1 και 8080, και η αλλαγή έχει αποθηκευτεί χωρίς σφάλμα.

    γ.Ενεργοποίηστε το προφίλ δευτερόλεπτα.Πάτησε αριστερό κλικ στο εικονίδιο του ZeroOmega πάνω δεξιά στον Chrome και επίλεξτε Shadow AI Guard (αντί για [Direct]).

## 5.Κλείστε τον browser
