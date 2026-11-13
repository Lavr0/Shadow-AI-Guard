import sqlite3

db_name = 'admin_logs.db'

def init_db():
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,                                 
            target_domain TEXT,
            action_taken TEXT,
            matched_content TEXT
        )
    ''') # creates the the table for our database
    conn.commit()
    conn.close()
    '''Method used to add a new log to the database'''
    def add_log(client_ip, target_domain, action_taken, matched_content):
        conn = sqlite3.connect(db_name) #Reopens the database
        c = conn.cursor() #recreates the cursor
        c.execute('''
            INSERT INTO logs (client_ip, target_domain, action_taken, matched_content) 
            VALUES (?, ?, ?, ?)
        ''', (client_ip, target_domain, action_taken, matched_content))
        conn.commit()
        conn.close()

    def get_dashboard():
        conn = sqlite3.connect(db_name)
        conn.row_factory = sqlite3.Row  
        c = conn.cursor()
        
        logs = c.execute('SELECT * FROM logs ORDER BY id DESC LIMIT 50').fetchall()
        
        total_requests = c.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
        blocked_requests = c.execute("SELECT COUNT(*) FROM logs WHERE action_taken = 'blocked'").fetchone()[0]
        allowed_requests = c.execute("SELECT COUNT(*) FROM logs WHERE action_taken = 'allowed'").fetchone()[0]
        
        conn.close()
        return logs, total_requests, blocked_requests, allowed_requests
