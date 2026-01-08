"""
Security Chatbot Web Application
Flask-based custom UI with API key management, chatbot, guide, and fun facts
"""

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import os
import requests
from agent import SecurityChatbotSystem, config

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management
CORS(app)

# Store API keys in session (in production, use a database)
API_KEYS_STORE = {}

@app.route('/')
def index():
    """Main landing page with 4 buttons"""
    return render_template('index.html')

@app.route('/chatbot')
def chatbot_page():
    """Chatbot interface page"""
    # Check if API keys are set
    google_key = session.get('google_api_key') or os.environ.get('GOOGLE_API_KEY')
    virustotal_key = session.get('virustotal_api_key') or os.environ.get('VIRUSTOTAL_API_KEY')
    
    if not google_key:
        return render_template('api_warning.html', 
                             missing_keys=['Google API Key'],
                             redirect_to='chatbot')
    
    return render_template('chatbot.html')

@app.route('/api-keys')
def api_keys_page():
    """API key configuration page"""
    return render_template('api_keys.html')

@app.route('/api/validate-keys', methods=['POST'])
def validate_keys():
    """Validate API keys"""
    data = request.json
    google_key = data.get('google_api_key', '').strip()
    virustotal_key = data.get('virustotal_api_key', '').strip()
    
    results = {
        'google_valid': False,
        'virustotal_valid': False,
        'google_message': '',
        'virustotal_message': ''
    }
    
    # Validate Google API Key
    if google_key:
        try:
            # Test the Google API key by making a simple request
            test_url = f"https://generativelanguage.googleapis.com/v1/models?key={google_key}"
            response = requests.get(test_url, timeout=5)
            
            if response.status_code == 200:
                results['google_valid'] = True
                results['google_message'] = '✅ Valid Google API Key'
                # Store in session and environment
                session['google_api_key'] = google_key
                os.environ['GOOGLE_API_KEY'] = google_key
            else:
                results['google_message'] = f'❌ Invalid key (Status: {response.status_code})'
        except Exception as e:
            results['google_message'] = f'❌ Validation failed: {str(e)}'
    else:
        results['google_message'] = '⚠️ Google API Key is required'
    
    # Validate VirusTotal API Key (optional)
    if virustotal_key:
        try:
            # Test VirusTotal API key
            test_url = "https://www.virustotal.com/api/v3/users/current"
            headers = {"x-apikey": virustotal_key}
            response = requests.get(test_url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                results['virustotal_valid'] = True
                results['virustotal_message'] = '✅ Valid VirusTotal API Key'
                # Store in session and config
                session['virustotal_api_key'] = virustotal_key
                os.environ['VIRUSTOTAL_API_KEY'] = virustotal_key
                config.virustotal_api_key = virustotal_key
            else:
                results['virustotal_message'] = f'❌ Invalid key (Status: {response.status_code})'
        except Exception as e:
            results['virustotal_message'] = f'❌ Validation failed: {str(e)}'
    else:
        results['virustotal_valid'] = True  # Optional key
        results['virustotal_message'] = '⚠️ Optional (URL scanning will be limited)'
    
    return jsonify(results)

@app.route('/api/chat', methods=['POST'])
def chat():
    """Handle chat messages"""
    data = request.json
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({'error': 'No message provided'}), 400
    
    # Check if API key is set
    if not (session.get('google_api_key') or os.environ.get('GOOGLE_API_KEY')):
        return jsonify({'error': 'Google API Key not configured'}), 403
    
    try:
        # Initialize the chatbot system
        chatbot = SecurityChatbotSystem(config)
        
        # Process the query
        response = chatbot.process_query(user_message)
        
        return jsonify({
            'response': response,
            'success': True
        })
    
    except Exception as e:
        return jsonify({
            'error': f'Error processing message: {str(e)}',
            'success': False
        }), 500

@app.route('/guide')
def guide_page():
    """Tutorial/Guide page"""
    return render_template('guide.html')

@app.route('/fun-facts')
def fun_facts_page():
    """Fun Facts quiz page"""
    return render_template('fun_facts.html')

@app.route('/api/check-answer', methods=['POST'])
def check_answer():
    """Check if quiz answer is correct"""
    data = request.json
    question_id = data.get('question_id')
    selected_answer = data.get('answer')
    
    # Example questions (can be expanded)
    questions = {
        'q1': {
            'correct': 'B',
            'explanation': 'A passkey is a FIDO2 credential that replaces passwords with biometric or device-based authentication.'
        }
    }
    
    if question_id in questions:
        is_correct = (selected_answer == questions[question_id]['correct'])
        return jsonify({
            'correct': is_correct,
            'explanation': questions[question_id]['explanation']
        })
    
    return jsonify({'error': 'Question not found'}), 404

if __name__ == '__main__':
    print("=" * 70)
    print("🚀 SECURITY CHATBOT WEB UI")
    print("=" * 70)
    print("\n📍 Starting server at: http://localhost:5000")
    print("\n✨ Features:")
    print("  • Custom Web Interface")
    print("  • API Key Management")
    print("  • Interactive Chatbot")
    print("  • Tutorial Guide")
    print("  • Fun Facts Quiz")
    print("\n" + "=" * 70)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
