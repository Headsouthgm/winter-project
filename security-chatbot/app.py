"""
Web UI Application for Security Chatbot
Connects the AI Agent system with a web interface

File: app.py
Run with: python app.py
"""

import os
import asyncio
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import uuid

# Import your AI agent system
from ai_agent import (
    SecurityChatbotSystem,
    SecurityConfig,
    setup_api_keys,
    run_session
)

from google.adk.runners import Runner
from google.genai import types

# ============================================================================
# FLASK APP SETUP
# ============================================================================

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management
CORS(app)  # Enable CORS for API calls

# Initialize the AI agent system
config = SecurityConfig()
chatbot_system = None
runner_instance = None
session_service = None

# ============================================================================
# INITIALIZATION
# ============================================================================

def initialize_system():
    """Initialize the chatbot system on startup"""
    global chatbot_system, runner_instance, session_service
    
    print("🚀 Initializing Security Chatbot System...")
    
    # Setup API keys
    if not setup_api_keys():
        print("⚠️  Warning: API keys not configured properly")
        return False
    
    # Initialize chatbot system
    chatbot_system = SecurityChatbotSystem(config)
    chatbot_system.setup_session_service(use_database=False)
    session_service = chatbot_system.session_service
    
    # Create app and runner
    try:
        app_instance = chatbot_system.create_app()
        runner_instance = Runner(app=app_instance, session_service=session_service)
        print("✅ System initialized successfully!")
        return True
    except Exception as e:
        print(f"❌ Initialization failed: {e}")
        return False

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_or_create_session_id():
    """Get or create a unique session ID for the user"""
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    return session['session_id']

async def process_message_async(user_message: str, session_id: str):
    """Process user message asynchronously and return response"""
    if not runner_instance or not session_service:
        return {"error": "System not initialized"}
    
    try:
        # Get or create session
        try:
            chat_session = await session_service.create_session(
                app_name=config.app_name,
                user_id=config.user_id,
                session_id=session_id
            )
        except:
            chat_session = await session_service.get_session(
                app_name=config.app_name,
                user_id=config.user_id,
                session_id=session_id
            )
        
        # Classify query type
        query_type = chatbot_system.conversational_agent.classify_query(user_message)
        
        # Convert message to ADK format
        query_content = types.Content(
            role="user",
            parts=[types.Part(text=user_message)]
        )
        
        # Collect response
        response_text = ""
        async for event in runner_instance.run_async(
            user_id=config.user_id,
            session_id=chat_session.id,
            new_message=query_content
        ):
            if event.content and event.content.parts:
                text = event.content.parts[0].text
                if text and text != "None":
                    response_text += text
        
        return {
            "response": response_text,
            "query_type": query_type,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    """Main chat interface"""
    return render_template('index.html')

@app.route('/api/chat', methods=['POST'])
def chat():
    """Handle chat messages"""
    if not chatbot_system:
        return jsonify({"error": "System not initialized"}), 500
    
    data = request.json
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({"error": "No message provided"}), 400
    
    # Get session ID
    session_id = get_or_create_session_id()
    
    # Process message asynchronously
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(process_message_async(user_message, session_id))
    loop.close()
    
    return jsonify(result)

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Analyze security risk of user scenario"""
    if not chatbot_system:
        return jsonify({"error": "System not initialized"}), 500
    
    data = request.json
    scenario = data.get('scenario', '')
    
    if not scenario:
        return jsonify({"error": "No scenario provided"}), 400
    
    # Use risk assessment agent
    result = chatbot_system.risk_agent.assess_risk(scenario)
    report = chatbot_system.report_agent.generate_security_report(result)
    
    return jsonify({
        "risk_assessment": result,
        "report": report,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    """Scan URL for security threats"""
    if not chatbot_system:
        return jsonify({"error": "System not initialized"}), 500
    
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    # Use tool orchestration agent
    result = chatbot_system.tool_agent.check_url(url)
    
    return jsonify({
        "scan_result": result,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/check-password', methods=['POST'])
def check_password():
    """Check if password has been breached"""
    if not chatbot_system:
        return jsonify({"error": "System not initialized"}), 500
    
    data = request.json
    password_hash = data.get('password_hash', '')
    
    if not password_hash:
        return jsonify({"error": "No password hash provided"}), 400
    
    # Use tool orchestration agent
    result = chatbot_system.tool_agent.check_password_breach(password_hash)
    
    return jsonify({
        "breach_check": result,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    """Submit user feedback"""
    if not chatbot_system:
        return jsonify({"error": "System not initialized"}), 500
    
    data = request.json
    interaction_id = data.get('interaction_id', str(uuid.uuid4()))
    rating = data.get('rating', 0)
    comments = data.get('comments', '')
    
    # Use learning agent
    chatbot_system.learning_agent.collect_feedback(interaction_id, rating, comments)
    
    return jsonify({
        "success": True,
        "message": "Feedback received"
    })

@app.route('/api/status')
def status():
    """Check system status"""
    return jsonify({
        "status": "online" if chatbot_system else "offline",
        "agents": {
            "conversational": chatbot_system.conversational_agent.name if chatbot_system else None,
            "knowledge": chatbot_system.knowledge_agent.name if chatbot_system else None,
            "risk": chatbot_system.risk_agent.name if chatbot_system else None,
            "tools": chatbot_system.tool_agent.name if chatbot_system else None,
            "report": chatbot_system.report_agent.name if chatbot_system else None,
            "learning": chatbot_system.learning_agent.name if chatbot_system else None,
        },
        "model": config.model_name
    })

@app.route('/api/clear-session', methods=['POST'])
def clear_session():
    """Clear current chat session"""
    session.clear()
    return jsonify({"success": True, "message": "Session cleared"})

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("SECURITY CHATBOT - WEB UI")
    print("=" * 70)
    
    # Initialize system
    if initialize_system():
        print("\n🌐 Starting web server...")
        print("📍 Open your browser to: http://localhost:5000")
        print("Press CTRL+C to stop\n")
        
        # Run Flask app
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=False  # Prevent double initialization
        )
    else:
        print("\n❌ Failed to initialize system. Please check your configuration.")
        print("Make sure GOOGLE_API_KEY is set correctly.")