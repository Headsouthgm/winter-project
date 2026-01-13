import os
import requests
import base64
import hashlib
import time
import json
import zipfile
import io
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

try:
    import google.generativeai as genai
    print("✅ Google Generative AI imported successfully.")
    GENAI_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ google-generativeai not installed. Run: pip install google-generativeai")
    GENAI_AVAILABLE = False

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityConfig:
    model_name: str = "gemini-2.5-flash"  # ✅ Using original model
    virustotal_api_key: Optional[str] = None

config = SecurityConfig()

# ===================================================================
# MAIN CONVERSATIONAL AGENT
# ===================================================================
class MainConversationalAgent:
    def __init__(self, model):
        self.model = model
        self.name = "Main Conversational Agent"
    
    def respond(self, user_input: str) -> str:
        """Generate natural conversational response"""
        try:
            response = self.model.generate_content(user_input)
            return response.text
        except Exception as e:
            print(f"Error: {e}")
            return "I'm here to help with your security questions. What would you like to know?"

# ===================================================================
# PASSWORD SAFETY AGENT
# ===================================================================
class PasswordSafetyAgent:
    def __init__(self):
        self.name = "Password Safety Checker (HIBP)"
    
    def check_password(self, password: str) -> Dict[str, Any]:
        """Check password against Have I Been Pwned database"""
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=10
            )
            
            if response.status_code == 200:
                hashes = response.text.split('\n')
                
                for line in hashes:
                    if ':' in line:
                        hash_suffix, count = line.split(':')
                        if hash_suffix.strip() == suffix:
                            breach_count = int(count.strip())
                            return {
                                "safe": False,
                                "breached": True,
                                "breach_count": breach_count,
                                "risk_level": "CRITICAL",
                                "should_change": True,
                                "message": f"⚠️ DANGER: This password was exposed {breach_count:,} times in data breaches!",
                                "recommendations": [
                                    f"🚫 DO NOT use this password - it appeared in {breach_count:,} breaches",
                                    "Change it immediately on ALL accounts",
                                    "Use a unique, randomly generated password",
                                    "Enable two-factor authentication (2FA)",
                                    "Consider using a password manager (Bitwarden, 1Password)"
                                ]
                            }
                
                return {
                    "safe": True,
                    "breached": False,
                    "breach_count": 0,
                    "risk_level": "LOW",
                    "should_change": False,
                    "message": "✅ GOOD NEWS: This password has not been found in known data breaches",
                    "recommendations": [
                        "✅ Password appears safe from known breaches",
                        "Still ensure it's unique and not used elsewhere",
                        "Use 12-16+ characters with mixed case, numbers, symbols",
                        "Enable 2FA for additional security",
                        "Consider using a password manager"
                    ]
                }
            else:
                return {
                    "safe": None,
                    "error": True,
                    "message": f"Unable to check password (API error: {response.status_code})"
                }
                
        except Exception as e:
            return {
                "safe": None,
                "error": True,
                "message": f"Error checking password: {str(e)}"
            }

# ===================================================================
# URL SAFETY AGENT
# ===================================================================
class URLSafetyAgent:
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.name = "URL Safety Checker (VirusTotal)"
        self.virustotal_base_url = "https://www.virustotal.com/api/v3"
    
    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL safety using VirusTotal"""
        api_key = self.config.virustotal_api_key
        
        if not api_key:
            return {
                "safe": None,
                "error": True,
                "message": "VirusTotal API key not configured",
                "recommendations": ["Configure VirusTotal API key for URL scanning"]
            }
        
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            response = requests.get(
                f"{self.virustotal_base_url}/urls/{url_id}",
                headers={"x-apikey": api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                total = sum(stats.values())
                
                if malicious > 0:
                    risk_level = "CRITICAL"
                    safe = False
                    should_access = False
                    virus_possibility = f"{(malicious/total)*100:.1f}%"
                    message = f"⚠️ DANGER: {malicious}/{total} security vendors flagged this URL as MALICIOUS!"
                    recommendations = [
                        "🚫 DO NOT visit this URL!",
                        f"{malicious} security vendors detected threats",
                        "This URL may contain malware, phishing, or other threats",
                        "Report to IT security if received via email",
                        "Clear browser cache if already visited"
                    ]
                elif suspicious > 0:
                    risk_level = "HIGH"
                    safe = False
                    should_access = False
                    virus_possibility = f"{(suspicious/total)*100:.1f}%"
                    message = f"⚠️ WARNING: {suspicious}/{total} vendors flagged as SUSPICIOUS"
                    recommendations = [
                        "⚠️ Exercise EXTREME caution",
                        f"{suspicious} vendors flagged suspicious activity",
                        "Verify URL is from a legitimate, trusted source",
                        "Consider using a sandbox environment",
                        "Do not enter any personal information"
                    ]
                else:
                    risk_level = "LOW"
                    safe = True
                    should_access = True
                    virus_possibility = "0%"
                    message = f"✅ SAFE: {harmless}/{total} vendors found no threats"
                    recommendations = [
                        "✅ URL appears safe based on current analysis",
                        f"Scanned by {total} security vendors",
                        "Still verify the domain matches what you expect",
                        "Use HTTPS connections when possible",
                        "Keep your browser and security software updated"
                    ]
                
                return {
                    "safe": safe,
                    "should_access": should_access,
                    "risk_level": risk_level,
                    "virus_possibility": virus_possibility,
                    "detections": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "total_scans": total
                    },
                    "message": message,
                    "recommendations": recommendations
                }
            
            elif response.status_code == 404:
                return self._submit_url_for_scan(url, api_key)
            
            else:
                return {
                    "safe": None,
                    "error": True,
                    "message": f"VirusTotal API error: {response.status_code}"
                }
                
        except Exception as e:
            return {
                "safe": None,
                "error": True,
                "message": f"Error checking URL: {str(e)}"
            }
    
    def _submit_url_for_scan(self, url: str, api_key: str) -> Dict[str, Any]:
        """Submit URL to VirusTotal for first-time scanning"""
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
                    "safe": None,
                    "pending_scan": True,
                    "risk_level": "UNKNOWN",
                    "message": "⏳ URL submitted for scanning",
                    "recommendations": [
                        "This URL was not previously scanned",
                        "Check back in a few moments for results",
                        "Exercise caution until scan completes"
                    ]
                }
            else:
                return {
                    "safe": None,
                    "error": True,
                    "message": f"Failed to submit URL for scanning"
                }
        except Exception as e:
            return {
                "safe": None,
                "error": True,
                "message": f"Submission error: {str(e)}"
            }

# ===================================================================
# SECURITY KNOWLEDGE AGENT
# ===================================================================
class SecurityKnowledgeAgent:
    def __init__(self, model):
        self.model = model
        self.name = "Security Knowledge (NIST)"
        
        self.knowledge_base = {
            "password": {
                "term": "Password Security",
                "definition": "Strong passwords should be 12+ characters with mixed case, numbers, and symbols",
                "why_it_matters": "Weak passwords are the #1 cause of security breaches",
                "best_practices": [
                    "Use 12-16+ character passwords",
                    "Include uppercase, lowercase, numbers, symbols",
                    "Never reuse passwords across sites"
                ],
                "related_concepts": ["Authentication", "Password managers", "2FA"]
            },
        }
        
        self.nist_glossary = None
        self.nist_loaded = False
    
    def load_nist_glossary(self) -> bool:
        """Download NIST cybersecurity glossary database"""
        if self.nist_loaded:
            return True
        
        try:
            print("📥 Downloading NIST Cybersecurity Glossary...")
            url = "https://csrc.nist.gov/csrc/media/glossary/glossary-export.zip"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                    json_files = [f for f in z.namelist() if f.endswith('.json')]
                    if json_files:
                        with z.open(json_files[0]) as f:
                            self.nist_glossary = json.load(f)
                        print(f"✅ NIST Glossary loaded: {len(self.nist_glossary)} terms")
                        self.nist_loaded = True
                        return True
            
            print("⚠️ Could not load NIST glossary")
            return False
        except Exception as e:
            print(f"⚠️ NIST glossary download failed: {e}")
            return False
    
    def search_nist_glossary(self, term: str) -> Optional[Dict[str, Any]]:
        """Search NIST database for security term"""
        if not self.nist_loaded:
            self.load_nist_glossary()
        
        if not self.nist_glossary:
            return None
        
        term_lower = term.lower()
        for entry in self.nist_glossary:
            if isinstance(entry, dict):
                glossary_term = entry.get('term', '').lower()
                if term_lower in glossary_term or glossary_term in term_lower:
                    return {
                        "term": entry.get('term', ''),
                        "definition": entry.get('definition', ''),
                        "source": "NIST Cybersecurity Glossary",
                        "abbreviations": entry.get('abbreviations', [])
                    }
        return None
    
    def get_security_knowledge(self, question: str) -> Dict[str, Any]:
        """Get security knowledge from NIST or local database"""
        topic_normalized = question.lower().replace('-', ' ').replace('_', ' ')
        
        for key, value in self.knowledge_base.items():
            if key in topic_normalized:
                return value
        
        nist_result = self.search_nist_glossary(question)
        if nist_result:
            return {
                "term": nist_result['term'],
                "explanation": nist_result['definition'],
                "source": nist_result['source'],
                "why_it_matters": "Important for cybersecurity compliance and best practices",
                "recommendations": ["Consult security experts", "Review NIST standards"],
                "related_concepts": []
            }
        
        return {
            "term": question,
            "explanation": f"Security information about {question}",
            "why_it_matters": "Protects your data and privacy",
            "recommendations": ["Use strong passwords", "Enable 2FA", "Keep software updated"],
            "related_concepts": ["Authentication", "Authorization", "Encryption"]
        }

# ===================================================================
# REPORT GENERATOR
# ===================================================================
class ReportGenerator:
    def __init__(self):
        self.name = "Report Generator"
    
    def generate_password_report(self, result: Dict[str, Any]) -> str:
        """Generate password safety report"""
        recs = '\n'.join(f"  • {rec}" for rec in result.get('recommendations', []))
        
        return f"""
    {'=' * 70}
    PASSWORD SAFETY REPORT
    {'=' * 70}

    Status: {"✅ SAFE" if result.get('safe') else "⚠️ UNSAFE"}
    Risk Level: {result.get('risk_level', 'UNKNOWN')}
    
    {result.get('message', '')}
    
    Breach Information:
      • Found in breaches: {"YES" if result.get('breached') else "NO"}
      • Times exposed: {result.get('breach_count', 0):,}
      • Should change: {"YES - IMMEDIATELY" if result.get('should_change') else "No"}
    
    Recommendations:
    {recs}
    
    {'=' * 70}
        """
    
    def generate_url_report(self, url: str, result: Dict[str, Any]) -> str:
        """Generate URL safety report"""
        recs = '\n'.join(f"  • {rec}" for rec in result.get('recommendations', []))
        detections = result.get('detections', {})
        
        return f"""
    {'=' * 70}
    URL SAFETY REPORT
    {'=' * 70}

    URL: {url}
    Status: {"✅ SAFE" if result.get('safe') else "⚠️ UNSAFE"}
    Risk Level: {result.get('risk_level', 'UNKNOWN')}
    
    {result.get('message', '')}
    
    Security Analysis:
      • Safe to access: {"YES" if result.get('should_access') else "NO"}
      • Virus possibility: {result.get('virus_possibility', 'Unknown')}
      • Malicious detections: {detections.get('malicious', 0)}/{detections.get('total_scans', 0)}
      • Suspicious flags: {detections.get('suspicious', 0)}/{detections.get('total_scans', 0)}
    
    Recommendations:
    {recs}
    
    {'=' * 70}
        """
    
    def generate_knowledge_report(self, findings: Dict[str, Any]) -> str:
        """Generate security knowledge report with only Topic, Definition, Why It Matters, and Application"""
        
        applications = findings.get('recommendations', findings.get('best_practices', []))
        if isinstance(applications, list):
            app_text = '\n'.join(f"  • {app}" for app in applications)
        else:
            app_text = f"  • {str(applications)}"
        
        return f"""
    {'=' * 70}
    SECURITY KNOWLEDGE REPORT
    {'=' * 70}

    Topic: {findings.get('term', 'Security Information')}

    Definition:
    {findings.get('explanation', findings.get('definition', 'Information not available'))}

    Why It Matters:
    {findings.get('why_it_matters', 'Important for security')}

    Application:
    {app_text}

    {'=' * 70}
        """

# ===================================================================
# MAIN SECURITY CHATBOT SYSTEM
# ✅ HYBRID: Keywords for routing (no API call), AI only for responses
# ===================================================================
class SecurityChatbotSystem:
    SYSTEM_INSTRUCTION = """You are a Security Expert Chatbot Assistant with real-time threat detection capabilities.

Your Capabilities:
- Answer questions about security concepts (passwords, encryption, 2FA, VPNs, etc.)
- Assess security risks in user scenarios
- Scan URLs using VirusTotal API for malware and phishing detection
- Check passwords against Have I Been Pwned database (600M+ breached passwords)
- Access NIST Cybersecurity Glossary (3,000+ authoritative security terms)
- Provide best practices for data protection
- Explain compliance requirements (GDPR, HIPAA, SOC2, PCI-DSS)
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
- For password checks, provide specific breach exposure data
- For security concepts, reference authoritative NIST definitions

Security Topics You Cover:
- Password management and authentication (MFA, passwordless, biometrics)
- Network security (firewalls, VPNs, zero-trust architecture, network segmentation)
- Data encryption and hashing (AES, RSA, SHA-256, TLS/SSL)
- Phishing and social engineering (recognition, prevention, reporting)
- Malware detection and analysis (viruses, ransomware, trojans, spyware)
- Secure software development (OWASP Top 10, secure SDLC, code reviews)
- Cloud security (AWS, Azure, GCP, shared responsibility model)
- Compliance and regulations (GDPR, HIPAA, SOC2, ISO 27001)
- Incident response (detection, containment, eradication, recovery)
- Security awareness training (human factor, security culture)

Special Features & Tools:
- Real-time URL scanning with VirusTotal (70+ security vendors)
- Multi-engine malware detection and threat intelligence
- Password breach checking via Have I Been Pwned (k-Anonymity protocol)
- NIST Cybersecurity Glossary integration for authoritative definitions
- Professional security reports with risk levels and actionable recommendations

Response Guidelines:
- For general questions: Be conversational and friendly (2-3 sentences)
- For password checks: Generate detailed PASSWORD SAFETY REPORT
- For URL scans: Generate detailed URL SAFETY REPORT  
- For security definitions: Generate SECURITY KNOWLEDGE REPORT with NIST data
- Always prioritize user safety and provide actionable next steps

Remember: Security is about balancing protection with usability. Help users make informed decisions while maintaining a friendly, approachable tone!"""

    def __init__(self, config: SecurityConfig):
        self.config = config
        
        if not GENAI_AVAILABLE:
            print("❌ Google Generative AI not available")
            self.model = None
        else:
            api_key = os.environ.get('GOOGLE_API_KEY')
            if not api_key:
                print("❌ GOOGLE_API_KEY not set")
                self.model = None
            else:
                try:
                    genai.configure(api_key=api_key)
                    self.model = genai.GenerativeModel(
                        model_name=config.model_name,
                        system_instruction=self.SYSTEM_INSTRUCTION
                    )
                    print(f"✅ Model initialized: {config.model_name}")
                except Exception as e:
                    print(f"❌ Failed to initialize model: {e}")
                    self.model = None
        
        self.main_agent = MainConversationalAgent(self.model)
        self.password_agent = PasswordSafetyAgent()
        self.url_agent = URLSafetyAgent(config)
        self.knowledge_agent = SecurityKnowledgeAgent(self.model)
        self.report_generator = ReportGenerator()
        
        print("✅ All agents initialized successfully.")
        print("🎯 HYBRID MODE: Keywords for routing (saves API calls)")
    
    def process_query(self, user_input: str) -> str:
        """
        HYBRID: Use keywords for routing (no API call)
        Only use AI for generating responses (1 API call instead of 2)
        """
        
        user_lower = user_input.lower()
        
        # ===================================================================
        # KEYWORD ROUTING (No API call - saves quota!)
        # ===================================================================
        
        # 1. PASSWORD CHECK
        if any(keyword in user_lower for keyword in ['check password', 'password safe', 'password pwned', 'password breached', 'password secure']):
            print("🔐 TRIGGERED: Password Safety Agent (no AI call for routing)")
            password = self._extract_password(user_input)
            if password:
                result = self.password_agent.check_password(password)
                return self.report_generator.generate_password_report(result)
            else:
                return "Please provide a password to check. Example: 'Check password MyPassword123'"
        
        # 2. URL CHECK
        if any(keyword in user_lower for keyword in ['check url', 'check link', 'url safe', 'link safe', 'scan url', 'scan link', 'check website']):
            print("🌐 TRIGGERED: URL Safety Agent (no AI call for routing)")
            url = self._extract_url(user_input)
            if url:
                result = self.url_agent.check_url(url)
                return self.report_generator.generate_url_report(url, result)
            else:
                return "Please provide a URL to check. Example: 'Check URL https://example.com'"
        
        # 3. KNOWLEDGE QUERY
        if any(keyword in user_lower for keyword in ['what is', 'define', 'explain']):
            print("📚 TRIGGERED: Knowledge Agent (no AI call for routing)")
            try:
                ai_response = self.model.generate_content(user_input)  # Only 1 AI call here
                knowledge = self.knowledge_agent.get_security_knowledge(user_input)
                knowledge['explanation'] = ai_response.text
                return self.report_generator.generate_knowledge_report(knowledge)
            except Exception as e:
                print(f"Error: {e}")
                knowledge = self.knowledge_agent.get_security_knowledge(user_input)
                return self.report_generator.generate_knowledge_report(knowledge)
        
        # 4. DEFAULT: CONVERSATION
        print("💬 Using: Main Conversational Agent (1 AI call only)")
        return self.main_agent.respond(user_input)  # Only 1 AI call here
    
    def _extract_password(self, text: str) -> Optional[str]:
        """Extract password from user input"""
        words = text.split()
        for i, word in enumerate(words):
            if word.lower() in ['password', 'credential']:
                if i + 1 < len(words):
                    return words[i + 1].strip('.,!?"\'')
        return None
    
    def _extract_url(self, text: str) -> Optional[str]:
        """Extract URL from user input"""
        words = text.split()
        for word in words:
            word = word.strip('.,!?')
            if word.startswith('http://') or word.startswith('https://'):
                return word
            elif '.' in word and any(ext in word for ext in ['.com', '.org', '.net', '.edu', '.gov', '.io']):
                if len(word) > 4:
                    return f"https://{word}"
        return None

root_agent = None

if __name__ == "__main__":
    print("=" * 70)
    print("SECURITY CHATBOT - HYBRID MODE (API OPTIMIZED)")
    print("=" * 70)
    print("\n✅ Keywords for routing (saves 50% API calls)")
    print("✅ AI only for responses (gemini-2.5-flash: 20/day free)")
    print("⚠️  Hybrid mode: 1 call per message (20 messages/day max)")
    print("\n" + "=" * 70)