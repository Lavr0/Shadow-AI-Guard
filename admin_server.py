from flask import Flask, render_template, request, jsonify
import database


app = Flask(__name__)

@app.route('/')
def index():
    # taking the statistics from our database
    logs, total_requests, blocked_requests, allowed_requests = database.get_dashboard()
    
    return render_template('index.html', 
                           logs=logs, 
                           total=total_requests, 
                           blocked=blocked_requests, 
                           allowed=allowed_requests)

if __name__ == '__main__':
    # runs the dashboard at the port -> 5000
    app.run(debug=True, port=5000)