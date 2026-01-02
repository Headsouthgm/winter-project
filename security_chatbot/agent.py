import os
import requests
import base64
import hashlib
import time
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
    model_name: str = "gemini-2.5-flash"
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

# check for Google API key and VirusTotal API key
def setup_api_keys():
    # Check for Google API key
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
    
    # Check for VirusTotal API key
    if "VIRUSTOTAL_API_KEY" in os.environ:
        config.virustotal_api_key = os.environ["VIRUSTOTAL_API_KEY"]
        print("✅ VirusTotal API key found in environment.")
    else:
        print("⚠️  VirusTotal API key not found. URL/file scanning will be limited.")
        print("Set it with: export VIRUSTOTAL_API_KEY='your_key_here'")
    
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

# Calls external security APIs with REAL VirusTotal integration
class ToolOrchestrationAgent:
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.name = "Tool Orchestration"
        self.virustotal_base_url = "https://www.virustotal.com/api/v3"
    
    def scan_file(self, file_hash: str) -> Dict[str, Any]:
        """Scan file using VirusTotal API"""
        api_key = self.config.virustotal_api_key
        
        if not api_key:
            return {
                "error": "VirusTotal API key not configured",
                "tool": "VirusTotal",
                "status": "unavailable"
            }
        
        try:
            headers = {"x-apikey": api_key}
            response = requests.get(
                f"{self.virustotal_base_url}/files/{file_hash}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                return {
                    "tool": "VirusTotal",
                    "status": "malicious" if stats['malicious'] > 0 else "clean",
                    "detections": stats['malicious'],
                    "total_scans": sum(stats.values()),
                    "suspicious": stats.get('suspicious', 0),
                    "undetected": stats.get('undetected', 0),
                    "harmless": stats.get('harmless', 0)
                }
            elif response.status_code == 404:
                return {
                    "tool": "VirusTotal",
                    "status": "not_found",
                    "message": "File not found in VirusTotal database"
                }
            else:
                return {
                    "tool": "VirusTotal",
                    "status": "error",
                    "message": f"API error: {response.status_code}"
                }
                
        except requests.exceptions.RequestException as e:
            return {
                "tool": "VirusTotal",
                "status": "error",
                "message": f"Request failed: {str(e)}"
            }
    
    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL using VirusTotal API"""
        api_key = self.config.virustotal_api_key
        
        if not api_key:
            return {
                "error": "VirusTotal API key not configured",
                "virustotal": "unavailable"
            }
        
        try:
            # Generate URL ID for VirusTotal
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            # Try to get existing analysis
            response = requests.get(
                f"{self.virustotal_base_url}/urls/{url_id}",
                headers={"x-apikey": api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                is_malicious = stats.get('malicious', 0) > 0
                is_suspicious = stats.get('suspicious', 0) > 0
                
                return {
                    "url": url,
                    "virustotal": "malicious" if is_malicious else ("suspicious" if is_suspicious else "clean"),
                    "detections": stats.get('malicious', 0),
                    "total_scans": sum(stats.values()),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0)
                }
            
            elif response.status_code == 404:
                # URL not in database, submit for scanning
                return self._submit_url_for_scan(url, api_key)
            
            else:
                return {
                    "virustotal": "error",
                    "message": f"API error: {response.status_code}"
                }
                
        except requests.exceptions.RequestException as e:
            return {
                "virustotal": "error",
                "message": f"Request failed: {str(e)}"
            }
    
    def _submit_url_for_scan(self, url: str, api_key: str) -> Dict[str, Any]:
        """Submit URL to VirusTotal for scanning"""
        try:
            headers = {
                "x-apikey": api_key,
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            response = requests.post(
                f"{self.virustotal_base_url}/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            
            if response.status_code == 200:
                return {
                    "url": url,
                    "virustotal": "scanning",
                    "message": "URL submitted for scanning. Check back in a few moments.",
                    "scan_id": response.json()['data']['id']
                }
            else:
                return {
                    "virustotal": "error",
                    "message": f"Failed to submit URL: {response.status_code}"
                }
                
        except requests.exceptions.RequestException as e:
            return {
                "virustotal": "error",
                "message": f"Submission failed: {str(e)}"
            }
    
    def check_password_breach(self, password: str) -> Dict[str, Any]:
        """Check password using Have I Been Pwned API with k-Anonymity"""
        try:
            # Step 1: Hash the password with SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            
            # Step 2: Split hash into prefix (first 5 chars) and suffix (rest)
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Step 3: Query HIBP API with only the prefix (k-Anonymity)
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=10
            )
            
            if response.status_code == 200:
                # Step 4: Check if our suffix appears in the results
                hashes = response.text.split('\n')
                
                for line in hashes:
                    if ':' in line:
                        hash_suffix, count = line.split(':')
                        if hash_suffix.strip() == suffix:
                            breach_count = int(count.strip())
                            return {
                                "breached": True,
                                "breach_count": breach_count,
                                "tool": "Have I Been Pwned",
                                "status": "breached",
                                "message": f"⚠️ WARNING: This password has been exposed {breach_count:,} times in data breaches!",
                                "recommendation": "Choose a different, unique password immediately"
                            }
                
                # Password not found in breaches
                return {
                    "breached": False,
                    "breach_count": 0,
                    "tool": "Have I Been Pwned",
                    "status": "safe",
                    "message": "✅ Good news! This password has not been found in known data breaches.",
                    "recommendation": "Still ensure it's unique and not used elsewhere"
                }
            
            else:
                return {
                    "tool": "Have I Been Pwned",
                    "status": "error",
                    "message": f"API error: {response.status_code}"
                }
                
        except requests.exceptions.RequestException as e:
            return {
                "tool": "Have I Been Pwned",
                "status": "error",
                "message": f"Request failed: {str(e)}"
            }

# Formats findings into readable reports
class ReportGenerationAgent:
    def __init__(self):
        self.name = "Report Generation"
    
    def generate_security_report(self, findings: Dict[str, Any]) -> str:
        recommendations = findings.get('recommendations', ['Continue monitoring'])
        if isinstance(recommendations, list):
            rec_text = '\n'.join(f"- {rec}" for rec in recommendations)
        else:
            rec_text = str(recommendations)
            
        report = f"""
=== SECURITY SCAN REPORT ===

Executive Summary:
{findings.get('summary', 'Security assessment completed')}

Risk Level: {findings.get('risk_level', 'LOW')}

Detailed Findings:
{findings.get('details', 'No issues detected')}

Recommendations:
{rec_text}
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
    
    def setup_session_service(self, use_database: bool = False):
        if use_database:
            self.session_service = DatabaseSessionService(
                database_url="sqlite:///./security_chatbot.db"
            )
            print("✅ Database session service configured.")
        else:
            self.session_service = InMemorySessionService()
            print("✅ In-memory session service configured.")
    
    def create_app(self) -> App:
        if not self.model:
            raise Exception("Model not initialized. Check API keys.")
        
        main_agent = Agent(
            name="security_chatbot",
            model=self.model,
            instruction="""You are a security expert chatbot assistant.
            Your role is to help users understand security concepts, assess risks,
            and provide actionable security advice. Be clear, concise, and helpful."""
        )
        
        app = App(
            agent=main_agent,
            app_name=self.config.app_name
        )
        
        print(f"✅ App created: {self.config.app_name}")
        return app
    
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
        
        elif query_type == "url_scan":
            # Extract URL with improved handling
            words = user_input.split()
            url = None
            for word in words:
                word = word.strip('.,!?')
                # If it has http/https, use it directly
                if word.startswith('http://') or word.startswith('https://'):
                    url = word
                    break
                # If it has a domain extension, add https://
                elif '.' in word and any(ext in word for ext in ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co', '.uk']):
                    if len(word) > 4:
                        url = f"https://{word}"
                        break
            
            if url:
                print(f"🔍 Scanning URL with VirusTotal: {url}")
                scan_result = self.tool_agent.check_url(url)
                
                return self.report_agent.generate_security_report({
                    "summary": f"URL scan completed for: {url}",
                    "risk_level": scan_result.get('virustotal', 'UNKNOWN').upper(),
                    "details": f"VirusTotal detections: {scan_result.get('detections', 0)}/{scan_result.get('total_scans', 0)}",
                    "recommendations": self._get_url_recommendations(scan_result)
                })
            else:
                return "Please provide a valid URL to scan. Example: Is https://example.com safe?"
        
        elif query_type == "file_scan":
            return "File scanning requires a file hash. Please provide a SHA-256 hash to scan."
        
        elif query_type == "password_check":
            # Extract password from user input
            words = user_input.split()
            password = None
        
            # Look for password after keywords
            for i, word in enumerate(words):
                if word.lower() in ['password', 'credential']:
                    if i + 1 < len(words):
                        # Get the word after "password" or "credential"
                        password = words[i + 1].strip('.,!?"\'')
                        break
            
            if password:
                print(f"🔍 Checking password breach status with HIBP")
                breach_result = self.tool_agent.check_password_breach(password)
                
                return self.report_agent.generate_security_report({
                    "summary": f"Password breach check completed",
                    "risk_level": "CRITICAL" if breach_result.get('breached') else "LOW",
                    "details": breach_result.get('message', 'Check completed'),
                    "recommendations": self._get_password_recommendations(breach_result)
                })
            else:
                return "Please provide a password to check. Example: 'Check password Password123'"
                
        else:
            advice = self.knowledge_agent.get_security_advice(user_input)
            return str(advice)
    
    def _get_url_recommendations(self, scan_result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on URL scan results"""
        status = scan_result.get('virustotal', 'unknown')
        
        if status == 'malicious':
            return [
                "⚠️ DO NOT visit this URL!",
                "This URL has been flagged as malicious by multiple sources",
                "Report this to your IT security team if received via email",
                "Clear your browser cache if you already visited it"
            ]
        elif status == 'suspicious':
            return [
                "⚠️ Exercise extreme caution with this URL",
                f"{scan_result.get('suspicious', 0)} scanners flagged it as suspicious",
                "Verify the URL is from a legitimate trusted source",
                "Consider using a sandbox environment if you must access it"
            ]
        elif status == 'clean':
            return [
                "✅ This URL appears safe based on current analysis",
                "Still verify the domain matches what you expect",
                "Use HTTPS connections when possible",
                "Keep your browser and security software updated"
            ]
        elif status == 'scanning':
            return [
                "⏳ URL submitted for scanning",
                "This URL was not previously scanned",
                "Check back in a few moments for results",
                "Exercise caution until results are available"
            ]
        else:
            return [
                "❌ Unable to complete scan",
                "There may be an issue with the API or URL format",
                "Try again or contact support if issue persists"
            ]
    def _get_password_recommendations(self, breach_result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on password breach results"""
        if breach_result.get('breached'):
            breach_count = breach_result.get('breach_count', 0)
            return [
                f"⚠️ CRITICAL: This password appeared {breach_count:,} times in data breaches!",
                "🚫 DO NOT use this password anywhere",
                "Change it immediately on all accounts where you use it",
                "Use a unique, randomly generated password instead",
                "Consider using a password manager (1Password, Bitwarden, LastPass)",
                "Enable two-factor authentication (2FA) on all accounts"
            ]
        else:
            return [
                "✅ This password hasn't been found in known breaches",
                "Still ensure it's unique and not used on multiple sites",
                "Use a mix of uppercase, lowercase, numbers, and symbols",
                "Make it at least 12-16 characters long",
                "Consider using a password manager for strong, unique passwords",
                "Enable 2FA for extra security"
            ]

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
        "Is it safe to click this link: http://testphp.vulnweb.com/"
        "Check password Password123",  # ← NEW TEST
        "Check password MyUniqueP@ssw0rd2024!XYZ"  # ← NEW TEST
    ]
    
    for query in test_queries:
        print(f"\n📝 Query: {query}")
        response = system.process_query(query)
        print(f"💬 Response:\n{response}")
        print("-" * 70)

def create_root_agent():
    print("\n🌐 Creating root agent for ADK Web UI...")
    
    if not setup_api_keys():
        print("⚠️ Warning: API keys not configured")
        try:
            return Agent(
                name="security_chatbot",
                model=Gemini(model_name="gemini-2.5-flash"),
                instruction="⚠️ Error: GOOGLE_API_KEY not configured. Please set your API key."
            )
        except:
            return None
    
    system = SecurityChatbotSystem(config)
    system.setup_session_service(use_database=False)
    
    main_agent = Agent(
        name="security_chatbot",
        model=system.model,
        instruction="""You are a Security Expert Chatbot Assistant with real-time threat detection capabilities.

Your Capabilities:
- Answer questions about security concepts (passwords, encryption, 2FA, VPNs, etc.)
- Assess security risks in user scenarios
- Scan URLs using VirusTotal API for malware and phishing detection
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
- For URL scans, provide detailed threat analysis from VirusTotal

Security Topics You Cover:
- Password management and authentication
- Network security (firewalls, VPNs, zero-trust)
- Data encryption and hashing
- Phishing and social engineering
- Malware detection and analysis
- Secure software development
- Cloud security (AWS, Azure, GCP)
- Compliance and regulations
- Incident response
- Security awareness training

Special Features:
- Real-time URL scanning with VirusTotal
- Multi-engine malware detection
- Threat intelligence from 70+ security vendors

Remember: Security is about balancing protection with usability. Help users make informed decisions!"""
    )
    
    print("✅ Root agent created successfully!")
    return main_agent


root_agent = create_root_agent()

if __name__ == "__main__":
    main()