"""
AI Agent Development Kit Setup
Multi-Agent Security System Implementation

This file contains:
1. Fundamental code setup for Google ADK
2. Multi-agent architecture for security chatbot
3. Complete instructions for running the system

Author: Winter Project
Week: 1-2 (Initial Setup & Research)
"""

import os
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

# ============================================================================
# SECTION 1: ENVIRONMENT SETUP & IMPORTS
# ============================================================================

try:
    from google.adk.agents import Agent, LlmAgent
    from google.adk.apps.app import App, EventsCompactionConfig
    from google.adk.models.google_llm import Gemini
    from google.adk.sessions import DatabaseSessionService, InMemorySessionService
    from google.adk.runners import Runner
    from google.adk.tools.tool_context import ToolContext
    from google.genai import types
    print("✅ ADK components imported successfully.")
except ImportError as e:
    print(f"⚠️  ADK not installed. Run: pip install google-adk")
    print(f"Error details: {e}")


# ============================================================================
# SECTION 2: CONFIGURATION & CONSTANTS
# ============================================================================

class RiskLevel(Enum):
    """Risk severity levels for security assessments"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityConfig:
    """Configuration for security agent system"""
    model_name: str = "gemini-2.0-flash-exp"
    max_retry_attempts: int = 5
    retry_exp_base: int = 7
    retry_initial_delay: int = 1
    user_id: str = "default_user"
    app_name: str = "security-chatbot"
    
    # API endpoints for security tools (to be configured)
    virustotal_api_key: Optional[str] = None
    google_safe_browsing_key: Optional[str] = None
    hibp_api_key: Optional[str] = None  # Have I Been Pwned

# Initialize configuration
config = SecurityConfig()

# Configure retry options for LLM requests
retry_config = types.HttpRetryOptions(
    attempts=config.max_retry_attempts,
    exp_base=config.retry_exp_base,
    initial_delay=config.retry_initial_delay,
    http_status_codes=[429, 500, 503, 504],
)


# ============================================================================
# SECTION 3: API KEY SETUP
# ============================================================================

def setup_api_keys():
    """
    Setup API keys for the project.
    
    For Kaggle Notebooks:
        - Use UserSecretsClient to retrieve GOOGLE_API_KEY
    
    For local development:
        - Set environment variable: export GOOGLE_API_KEY="your_key_here"
        - Or create a .env file with your keys
    """
    try:
        # Try Kaggle Secrets first
        from kaggle_secrets import UserSecretsClient
        GOOGLE_API_KEY = UserSecretsClient().get_secret("GOOGLE_API_KEY")
        os.environ["GOOGLE_API_KEY"] = GOOGLE_API_KEY
        print("✅ Gemini API key setup complete (Kaggle).")
    except:
        # Fall back to environment variable
        if "GOOGLE_API_KEY" in os.environ:
            print("✅ Gemini API key found in environment.")
        else:
            print("🔑 WARNING: GOOGLE_API_KEY not found!")
            print("Please set it using: export GOOGLE_API_KEY='your_key_here'")
            return False
    return True


# ============================================================================
# SECTION 4: AGENT DEFINITIONS
# ============================================================================

class ConversationalAgent:
    """
    Agent 1: Conversational Interface Agent
    
    Purpose: Handle user interaction and route requests
    Responsibilities:
        - Understand user questions in natural language
        - Classify query type (question/scan/risk assessment)
        - Maintain conversation context
        - Present results in user-friendly format
    """
    
    def __init__(self, model: Gemini):
        self.model = model
        self.name = "Conversational Interface"
    
    def classify_query(self, user_input: str) -> str:
        """Classify the type of user query"""
        user_input_lower = user_input.lower()
        
        if any(word in user_input_lower for word in ['scan', 'check file', 'virus', 'malware']):
            return "file_scan"
        elif any(word in user_input_lower for word in ['link', 'url', 'website', 'phishing']):
            return "url_scan"
        elif any(word in user_input_lower for word in ['password', 'credential', 'been pwned']):
            return "password_check"
        elif any(word in user_input_lower for word in ['risk', 'safe to', 'should i', 'is it okay']):
            return "risk_assessment"
        else:
            return "knowledge_query"
    
    def route_request(self, query_type: str, user_input: str) -> str:
        """Route request to appropriate agent"""
        routing_map = {
            "file_scan": "Tool Orchestration Agent",
            "url_scan": "Tool Orchestration Agent",
            "password_check": "Tool Orchestration Agent",
            "risk_assessment": "Risk Assessment Agent",
            "knowledge_query": "Security Knowledge Agent"
        }
        return routing_map.get(query_type, "Security Knowledge Agent")


class SecurityKnowledgeAgent:
    """
    Agent 2: Security Knowledge Agent
    
    Purpose: Answer security questions using expert knowledge
    Knowledge Domains:
        - Password security
        - Network security
        - Data encryption
        - Access control
        - Compliance (GDPR, HIPAA, SOC2)
    """
    
    def __init__(self, model: Gemini):
        self.model = model
        self.name = "Security Knowledge"
        self.knowledge_base = {
            "password": "Strong passwords should be 12+ characters with mixed case, numbers, and symbols.",
            "encryption": "Encryption converts data into unreadable format; hashing is one-way transformation.",
            "vpn": "VPN encrypts your internet connection, essential for public WiFi and remote work.",
            "2fa": "Two-factor authentication adds extra security layer beyond just passwords.",
        }
    
    def get_security_advice(self, topic: str) -> Dict[str, Any]:
        """Retrieve security advice for a given topic"""
        return {
            "explanation": f"Security information about {topic}",
            "why_it_matters": "Protects your data and privacy",
            "recommendations": ["Use strong passwords", "Enable 2FA", "Keep software updated"],
            "related_concepts": ["Authentication", "Authorization", "Encryption"]
        }


class RiskAssessmentAgent:
    """
    Agent 3: Risk Assessment Agent
    
    Purpose: Analyze user actions for security implications
    Risk Categories:
        - Password management risks
        - Data sharing risks
        - Phishing susceptibility
        - Social engineering vulnerabilities
    """
    
    def __init__(self, model: Gemini):
        self.model = model
        self.name = "Risk Assessment"
    
    def assess_risk(self, scenario: str) -> Dict[str, Any]:
        """Assess security risk of a given scenario"""
        # Simple keyword-based risk assessment (to be enhanced with LLM)
        risk_keywords = {
            RiskLevel.CRITICAL: ['password', 'database', 'customer data', 'personal gmail'],
            RiskLevel.HIGH: ['share', 'email', 'usb drive', 'public wifi'],
            RiskLevel.MEDIUM: ['download', 'attachment', 'link'],
            RiskLevel.LOW: ['question', 'ask', 'learn']
        }
        
        scenario_lower = scenario.lower()
        risk_level = RiskLevel.LOW
        
        for level, keywords in risk_keywords.items():
            if any(keyword in scenario_lower for keyword in keywords):
                risk_level = level
                break
        
        return {
            "risk_level": risk_level.value,
            "reasons": ["Action involves sensitive data", "Unencrypted transmission"],
            "consequences": ["Data breach", "Compliance violation"],
            "recommendations": ["Use secure file sharing", "Enable encryption"]
        }


class ToolOrchestrationAgent:
    """
    Agent 4: Tool Orchestration Agent
    
    Purpose: Coordinate external security tools and APIs
    Available Tools:
        - VirusTotal (malware detection)
        - Google Safe Browsing (phishing/malware URLs)
        - Have I Been Pwned (breach checking)
        - SSL Labs (certificate validation)
    """
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.name = "Tool Orchestration"
    
    def scan_file(self, file_hash: str) -> Dict[str, Any]:
        """Scan file using VirusTotal API"""
        # Placeholder - implement actual API call
        return {
            "tool": "VirusTotal",
            "status": "clean",
            "detections": 0,
            "total_scans": 70
        }
    
    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL safety using multiple services"""
        # Placeholder - implement actual API calls
        return {
            "safe_browsing": "safe",
            "virustotal": "clean",
            "phishtank": "not_found"
        }
    
    def check_password_breach(self, password_hash: str) -> Dict[str, Any]:
        """Check if password appears in known breaches"""
        # Placeholder - implement HIBP API call
        return {
            "breached": False,
            "breach_count": 0
        }


class ReportGenerationAgent:
    """
    Agent 5: Report Generation Agent
    
    Purpose: Create comprehensive security reports
    Report Components:
        - Executive summary
        - Risk level (color-coded)
        - Detailed findings
        - Remediation steps
    """
    
    def __init__(self):
        self.name = "Report Generation"
    
    def generate_security_report(self, findings: Dict[str, Any]) -> str:
        """Generate formatted security report"""
        report = f"""
        === SECURITY SCAN REPORT ===
        
        Executive Summary:
        {findings.get('summary', 'Security assessment completed')}
        
        Risk Level: {findings.get('risk_level', 'LOW')}
        
        Detailed Findings:
        {findings.get('details', 'No issues detected')}
        
        Recommendations:
        {', '.join(findings.get('recommendations', ['Continue monitoring']))}
        """
        return report


class LearningAgent:
    """
    Agent 6: Learning & Improvement Agent
    
    Purpose: Improve system over time based on feedback
    Responsibilities:
        - Track user satisfaction
        - Identify knowledge gaps
        - Update threat intelligence
    """
    
    def __init__(self):
        self.name = "Learning & Improvement"
        self.feedback_data = []
    
    def collect_feedback(self, interaction_id: str, rating: int, comments: str):
        """Collect user feedback"""
        self.feedback_data.append({
            "id": interaction_id,
            "rating": rating,
            "comments": comments
        })
    
    def analyze_feedback(self) -> Dict[str, Any]:
        """Analyze collected feedback for improvements"""
        if not self.feedback_data:
            return {"average_rating": 0, "insights": []}
        
        avg_rating = sum(f["rating"] for f in self.feedback_data) / len(self.feedback_data)
        return {
            "average_rating": avg_rating,
            "total_interactions": len(self.feedback_data),
            "insights": ["System performing well"]
        }


# ============================================================================
# SECTION 5: MAIN AGENT SYSTEM
# ============================================================================

class SecurityChatbotSystem:
    """
    Main system that coordinates all agents
    """
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.session_service = None
        self.runner = None
        
        # Initialize model
        try:
            self.model = Gemini(model_name=config.model_name)
            print(f"✅ Model initialized: {config.model_name}")
        except Exception as e:
            print(f"❌ Failed to initialize model: {e}")
            self.model = None
        
        # Initialize all agents
        self.conversational_agent = ConversationalAgent(self.model) if self.model else None
        self.knowledge_agent = SecurityKnowledgeAgent(self.model) if self.model else None
        self.risk_agent = RiskAssessmentAgent(self.model) if self.model else None
        self.tool_agent = ToolOrchestrationAgent(config)
        self.report_agent = ReportGenerationAgent()
        self.learning_agent = LearningAgent()
        
        print("✅ All agents initialized successfully.")
    
    def setup_session_service(self, use_database: bool = False):
        """Setup session service for conversation history"""
        if use_database:
            # Use DatabaseSessionService for persistent storage
            self.session_service = DatabaseSessionService(
                database_url="sqlite:///./security_chatbot.db"
            )
            print("✅ Database session service configured.")
        else:
            # Use InMemorySessionService for testing
            self.session_service = InMemorySessionService()
            print("✅ In-memory session service configured.")
    
    def create_app(self) -> App:
        """Create the main application"""
        if not self.model:
            raise Exception("Model not initialized. Check API keys.")
        
        # Create the main agent
        main_agent = LlmAgent(
            model=self.model,
            system_instruction="""You are a security expert chatbot assistant.
            Your role is to help users understand security concepts, assess risks,
            and provide actionable security advice. Be clear, concise, and helpful."""
        )
        
        # Create the app
        app = App(
            agent=main_agent,
            app_name=self.config.app_name
        )
        
        print(f"✅ App created: {self.config.app_name}")
        return app
    
    def process_query(self, user_input: str) -> str:
        """Process user query through the agent system"""
        if not self.conversational_agent:
            return "Error: System not properly initialized."
        
        # Step 1: Classify query
        query_type = self.conversational_agent.classify_query(user_input)
        print(f"📊 Query classified as: {query_type}")
        
        # Step 2: Route to appropriate agent
        target_agent = self.conversational_agent.route_request(query_type, user_input)
        print(f"🔀 Routing to: {target_agent}")
        
        # Step 3: Process based on query type
        if query_type == "risk_assessment":
            result = self.risk_agent.assess_risk(user_input)
            return self.report_agent.generate_security_report(result)
        
        elif query_type in ["file_scan", "url_scan", "password_check"]:
            # Use tool orchestration
            result = {"summary": "Tool scan completed", "risk_level": "LOW"}
            return self.report_agent.generate_security_report(result)
        
        else:
            # Knowledge query
            advice = self.knowledge_agent.get_security_advice(user_input)
            return str(advice)


# ============================================================================
# SECTION 6: HELPER FUNCTIONS
# ============================================================================

async def run_session(
    runner_instance: Runner,
    session_service: Any,
    user_queries: List[str] | str,
    session_name: str = "default",
    user_id: str = "default_user"
):
    """
    Helper function to manage conversation sessions
    
    Args:
        runner_instance: Runner instance for the app
        session_service: Session service for managing state
        user_queries: Single query string or list of queries
        session_name: Unique identifier for the session
        user_id: User identifier
    """
    print(f"\n### Session: {session_name}")
    
    app_name = runner_instance.app_name
    
    # Create or retrieve session
    try:
        session = await session_service.create_session(
            app_name=app_name,
            user_id=user_id,
            session_id=session_name
        )
    except:
        session = await session_service.get_session(
            app_name=app_name,
            user_id=user_id,
            session_id=session_name
        )
    
    # Process queries
    if user_queries:
        if isinstance(user_queries, str):
            user_queries = [user_queries]
        
        for query in user_queries:
            print(f"\nUser > {query}")
            
            # Convert to ADK Content format
            query_content = types.Content(
                role="user",
                parts=[types.Part(text=query)]
            )
            
            # Stream response
            async for event in runner_instance.run_async(
                user_id=user_id,
                session_id=session.id,
                new_message=query_content
            ):
                if event.content and event.content.parts:
                    text = event.content.parts[0].text
                    if text and text != "None":
                        print(f"Agent > {text}")
    else:
        print("No queries provided!")


# ============================================================================
# SECTION 7: MAIN EXECUTION & INSTRUCTIONS
# ============================================================================

def main():
    """
    Main execution function
    """
    print("=" * 70)
    print("SECURITY CHATBOT - AI AGENT SYSTEM")
    print("Winter Project - Week 1-2: Setup & Research")
    print("=" * 70)
    
    # Step 1: Setup API keys
    if not setup_api_keys():
        print("\n❌ Cannot proceed without API keys.")
        return
    
    # Step 2: Initialize system
    system = SecurityChatbotSystem(config)
    
    # Step 3: Setup session service
    system.setup_session_service(use_database=False)
    
    # Step 4: Test the system (synchronous example)
    print("\n" + "=" * 70)
    print("TESTING AGENT SYSTEM")
    print("=" * 70)
    
    test_queries = [
        "What is two-factor authentication?",
        "I want to share my password with a coworker",
        "Is it safe to click this link: example.com"
    ]
    
    for query in test_queries:
        print(f"\n📝 Query: {query}")
        response = system.process_query(query)
        print(f"💬 Response:\n{response}")
        print("-" * 70)


"""
============================================================================
INSTRUCTIONS FOR RUNNING THIS CODE
============================================================================

SETUP (Week 1):
---------------
1. Install required packages:
   pip install google-adk

2. Get your Gemini API key:
   - Visit: https://aistudio.google.com/apikey
   - Create a new API key
   - Save it securely

3. Set up API key:
   
   For Kaggle Notebooks:
   - Add GOOGLE_API_KEY to Kaggle Secrets
   - Enable the secret in your notebook
   
   For Local Development:
   - Linux/Mac: export GOOGLE_API_KEY="your_key_here"
   - Windows: set GOOGLE_API_KEY=your_key_here
   - Or create .env file with: GOOGLE_API_KEY=your_key_here

4. Run this file:
   python ai_agent.py


DEVELOPMENT ROADMAP (Weeks 2-8):
--------------------------------

Week 2: Research & Requirements
- Test all agent classifications
- Document conversation flows
- Research security APIs (VirusTotal, HIBP)

Week 3: Initial Prototype
- Implement actual API integrations
- Add database for chat history
- Create basic web interface

Week 4: Refinement
- Build responsive UI
- Improve response quality
- Add conversation history panel

Week 5: Mid-Project Review
- Demo current capabilities
- Identify challenges
- Adjust timeline if needed

Week 6: Advanced Features
- Implement user feedback system
- Add conversation management
- Improve error handling

Week 7: Testing & Refinement
- Comprehensive testing
- Bug fixes
- Performance optimization
- Prepare final presentation

Week 8: Final Presentation
- Complete demo
- Project report
- Future roadmap


ARCHITECTURE NOTES:
------------------
This system uses a multi-agent architecture:

1. ConversationalAgent: Routes user queries
2. SecurityKnowledgeAgent: Answers security questions
3. RiskAssessmentAgent: Assesses security risks
4. ToolOrchestrationAgent: Calls external APIs
5. ReportGenerationAgent: Formats results
6. LearningAgent: Improves over time

Each agent specializes in one aspect of security assistance,
and they work together to provide comprehensive help.


NEXT STEPS:
----------
1. Run this file to test the basic setup
2. Implement actual API integrations
3. Create a web interface (Flask/FastAPI)
4. Add persistent storage (SQLite/PostgreSQL)
5. Deploy to production (Week 8)


RESOURCES:
---------
- Google ADK Docs: https://developers.google.com/adk
- Gemini API: https://ai.google.dev/docs
- VirusTotal API: https://www.virustotal.com/gui/
- Have I Been Pwned: https://haveibeenpwned.com/API


For questions or issues, refer to the project README.md
============================================================================
"""

if __name__ == "__main__":
    main()
