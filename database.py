import psycopg2
import os

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "shadow_ai_db"),
    "user": os.getenv("DB_USER", "shadow_user"),
    "password": os.getenv("DB_PASSWORD", "shadow_password"),
    "host": os.getenv("DB_HOST", "db"),  # Εδώ το "db" είναι το όνομα της υπηρεσίας στο docker-compose!
    "port": os.getenv("DB_PORT", "5432")
}


def init_db():
    conn = psycopg2.connect(**DB_CONFIG)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            client_ip VARCHAR(50),                            
            target_domain VARCHAR(255),
            action_taken VARCHAR(20),
            matched_content TEXT
        )
    ''')
    conn.commit()
    c.close()
    conn.close()

def add_log(client_ip, target_domain, action_taken, matched_content):
    conn = psycopg2.connect(**DB_CONFIG)
    c = conn.cursor()
    c.execute('''
        INSERT INTO logs (client_ip, target_domain, action_taken, matched_content) 
        VALUES (%s, %s, %s, %s)
    ''', (client_ip, target_domain, action_taken, matched_content))
    conn.commit()
    c.close()
    conn.close()

def get_dashboard():
    conn = psycopg2.connect(**DB_CONFIG)
    c = conn.cursor()
    
    c.execute('SELECT id, timestamp, client_ip, target_domain, action_taken, matched_content FROM logs ORDER BY id DESC LIMIT 50')
    rows = c.fetchall()
    
    logs = []
    for row in rows:
        logs.append({
            "id": row[0],
            "timestamp": row[1],
            "client_ip": row[2],
            "target_domain": row[3],
            "action_taken": row[4],
            "matched_content": row[5]
        })
    
    c.execute('SELECT COUNT(*) FROM logs')
    total_requests = c.fetchone()[0] 
    
    c.execute("SELECT COUNT(*) FROM logs WHERE action_taken = 'blocked'")
    blocked_requests = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM logs WHERE action_taken = 'allowed'")
    allowed_requests = c.fetchone()[0]
    
    c.close()
    conn.close()
    
    return logs, total_requests, blocked_requests, allowed_requests
