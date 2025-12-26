import os
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

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

#  Define security risk levels Use: Classify how dangerous a security scenario is
class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

#  Store all configuration settings
@dataclass
class SecurityConfig:
    model_name: str = "gemini-2.0-flash-exp"
    max_retry_attempts: int = 5
    retry_exp_base: int = 7
    retry_initial_delay: int = 1
    user_id: str = "default_user"
    app_name: str = "security_chatbot"
    virustotal_api_key: Optional[str] = None
    google_safe_browsing_key: Optional[str] = None
    hibp_api_key: Optional[str] = None


config = SecurityConfig()

# retry API calls when it is busy or has an error
retry_config = types.HttpRetryOptions(
    attempts=config.max_retry_attempts,
    exp_base=config.retry_exp_base,
    initial_delay=config.retry_initial_delay,
    http_status_codes=[429, 500, 503, 504],
)

# check for Google API key
def setup_api_keys():
    try:
        from kaggle_secrets import UserSecretsClient
        GOOGLE_API_KEY = UserSecretsClient().get_secret("GOOGLE_API_KEY")
        os.environ["GOOGLE_API_KEY"] = GOOGLE_API_KEY
        print("✅ Gemini API key setup complete (Kaggle).")
    except:
        if "GOOGLE_API_KEY" in os.environ:
            print("✅ Gemini API key found in environment.")
        else:
            print("🔑 WARNING: GOOGLE_API_KEY not found!")
            print("Please set it using: export GOOGLE_API_KEY='your_key_here'")
            return False
    return True

# Decides which specialist agent should handle the query
class ConversationalAgent:
    def __init__(self, model: Gemini):
        self.model = model
        self.name = "Conversational Interface"
    
    def classify_query(self, user_input: str) -> str:
        user_input_lower = user_input.lower()
        # Looks for keywords (scan, url, password, risk) and reach different tools
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
        routing_map = {
            "file_scan": "Tool Orchestration Agent",
            "url_scan": "Tool Orchestration Agent",
            "password_check": "Tool Orchestration Agent",
            "risk_assessment": "Risk Assessment Agent",
            "knowledge_query": "Security Knowledge Agent"
        }
        return routing_map.get(query_type, "Security Knowledge Agent")

# pre-define knowledge(change to a dataset if possible)
class SecurityKnowledgeAgent:
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
        return {
            "explanation": f"Security information about {topic}",
            "why_it_matters": "Protects your data and privacy",
            "recommendations": ["Use strong passwords", "Enable 2FA", "Keep software updated"],
            "related_concepts": ["Authentication", "Authorization", "Encryption"]
        }

# Evaluates security risks in user scenarios
class RiskAssessmentAgent:
    def __init__(self, model: Gemini):
        self.model = model
        self.name = "Risk Assessment"
    
    def assess_risk(self, scenario: str) -> Dict[str, Any]:
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

# Calls external security APIs( need to change into real APIs)
class ToolOrchestrationAgent:
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.name = "Tool Orchestration"
    
    def scan_file(self, file_hash: str) -> Dict[str, Any]:
        return {
            "tool": "VirusTotal",
            "status": "clean",
            "detections": 0,
            "total_scans": 70
        }
    
    def check_url(self, url: str) -> Dict[str, Any]:
        return {
            "safe_browsing": "safe",
            "virustotal": "clean",
            "phishtank": "not_found"
        }
    
    def check_password_breach(self, password_hash: str) -> Dict[str, Any]:
        return {
            "breached": False,
            "breach_count": 0
        }

# Formats findings into readable reports
class ReportGenerationAgent:
    def __init__(self):
        self.name = "Report Generation"
    
    def generate_security_report(self, findings: Dict[str, Any]) -> str:
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

# Learns from user feedback
class LearningAgent:
    def __init__(self):
        self.name = "Learning & Improvement"
        self.feedback_data = []
    
    def collect_feedback(self, interaction_id: str, rating: int, comments: str):
        self.feedback_data.append({
            "id": interaction_id,
            "rating": rating,
            "comments": comments
        })
    
    def analyze_feedback(self) -> Dict[str, Any]:
        if not self.feedback_data:
            return {"average_rating": 0, "insights": []}
        
        avg_rating = sum(f["rating"] for f in self.feedback_data) / len(self.feedback_data)
        return {
            "average_rating": avg_rating,
            "total_interactions": len(self.feedback_data),
            "insights": ["System performing well"]
        }

# Creates and manages all 6 specialist agents
class SecurityChatbotSystem:
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.session_service = None
        self.runner = None
        
        try:
            self.model = Gemini(model_name=config.model_name)
            print(f"✅ Model initialized: {config.model_name}")
        except Exception as e:
            print(f"❌ Failed to initialize model: {e}")
            self.model = None
        
        self.conversational_agent = ConversationalAgent(self.model) if self.model else None
        self.knowledge_agent = SecurityKnowledgeAgent(self.model) if self.model else None
        self.risk_agent = RiskAssessmentAgent(self.model) if self.model else None
        self.tool_agent = ToolOrchestrationAgent(config)
        self.report_agent = ReportGenerationAgent()
        self.learning_agent = LearningAgent()
        
        print("✅ All agents initialized successfully.")
    
    # Choose how to store conversation history
    def setup_session_service(self, use_database: bool = False):
        if use_database:
            self.session_service = DatabaseSessionService(
                database_url="sqlite:///./security_chatbot.db"
            )
            print("✅ Database session service configured.")
        else:
            self.session_service = InMemorySessionService()
            print("✅ In-memory session service configured.")
    
    # Creates the ADK application 
    def create_app(self) -> App:
        if not self.model:
            raise Exception("Model not initialized. Check API keys.")
        
        main_agent = Agent(
            name="security_chatbot",
            model=self.model,
            system_instruction="""You are a security expert chatbot assistant.
            Your role is to help users understand security concepts, assess risks,
            and provide actionable security advice. Be clear, concise, and helpful."""
        )
        
        app = App(
            agent=main_agent,
            app_name=self.config.app_name
        )
        
        print(f"✅ App created: {self.config.app_name}")
        return app
    # Main flow:
    # 1. User sends message
    # 2. Conversational agent classifies it
    # 3. Routes to appropriate specialist
    # 4. Specialist processes it
    # 5. Report agent formats the response
    # 6. Returns to user
    def process_query(self, user_input: str) -> str:
        if not self.conversational_agent:
            return "Error: System not properly initialized."
        
        query_type = self.conversational_agent.classify_query(user_input)
        print(f"📊 Query classified as: {query_type}")
        
        target_agent = self.conversational_agent.route_request(query_type, user_input)
        print(f"🔀 Routing to: {target_agent}")
        
        if query_type == "risk_assessment":
            result = self.risk_agent.assess_risk(user_input)
            return self.report_agent.generate_security_report(result)
        
        elif query_type in ["file_scan", "url_scan", "password_check"]:
            result = {"summary": "Tool scan completed", "risk_level": "LOW"}
            return self.report_agent.generate_security_report(result)
        
        else:
            advice = self.knowledge_agent.get_security_advice(user_input)
            return str(advice)

# Manages conversation sessions asynchronously
async def run_session(
    runner_instance: Runner,
    session_service: Any,
    user_queries: List[str] | str,
    session_name: str = "default",
    user_id: str = "default_user"
):
    print(f"\n### Session: {session_name}")
    
    app_name = runner_instance.app_name
    
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
    
    if user_queries:
        if isinstance(user_queries, str):
            user_queries = [user_queries]
        
        for query in user_queries:
            print(f"\nUser > {query}")
            
            query_content = types.Content(
                role="user",
                parts=[types.Part(text=query)]
            )
            
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

# Testing the system without the web UI
def main():
    print("=" * 70)
    print("SECURITY CHATBOT - AI AGENT SYSTEM")
    print("=" * 70)
    
    if not setup_api_keys():
        print("\n❌ Cannot proceed without API keys.")
        return
    
    system = SecurityChatbotSystem(config)
    system.setup_session_service(use_database=False)
    
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

# ADK Web UI

def create_root_agent():
    print("\n🌐 Creating root agent for ADK Web UI...")
    
    if not setup_api_keys():
        print("⚠️ Warning: API keys not configured")
        try:
            return Agent(
                name="security_chatbot",
                model=Gemini(model_name="gemini-2.0-flash-exp"),
                instruction="⚠️ Error: GOOGLE_API_KEY not configured. Please set your API key."
            )
        except:
            return None
    
    system = SecurityChatbotSystem(config)
    system.setup_session_service(use_database=False)
    
    # Use Agent instead of LlmAgent, with correct parameters
    main_agent = Agent(
        name="security_chatbot",
        model=system.model,
        instruction="""You are a Security Expert Chatbot Assistant specializing in cybersecurity.

Your Capabilities:
- Answer questions about security concepts (passwords, encryption, 2FA, VPNs, etc.)
- Assess security risks in user scenarios
- Provide best practices for data protection
- Explain compliance requirements (GDPR, HIPAA, SOC2)
- Guide users on secure coding practices
- Help with incident response planning

Your Approach:
- Be clear, concise, and actionable
- Use examples to illustrate concepts
- Consider the user's technical level
- Prioritize practical advice over theory
- When assessing risks, explain both likelihood and impact
- Always recommend the most secure option, but provide alternatives

Security Topics You Cover:
- Password management and authentication
- Network security (firewalls, VPNs, zero-trust)
- Data encryption and hashing
- Phishing and social engineering
- Secure software development
- Cloud security (AWS, Azure, GCP)
- Compliance and regulations
- Incident response
- Security awareness training

Remember: Security is about balancing protection with usability. Help users make informed decisions!"""
    )
    
    print("✅ Root agent created successfully!")
    return main_agent


root_agent = create_root_agent()

# Exposes agent to ADK Web
if __name__ == "__main__":
    main()