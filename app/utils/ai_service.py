"""
AI-Assisted Vulnerability Analysis Service
Uses Groq API for fast, cloud-based LLM analysis
"""

import json
import os
import re
import time
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class AIPrioritizer:
    """AI-powered vulnerability analysis using Groq API."""

    def __init__(self, model=None):
        self.model = model or os.environ.get('GROQ_MODEL', 'llama-3.3-70b-versatile')
        self.api_key = os.environ.get('GROQ_API_KEY')
        self.timeout = int(os.environ.get('AI_TIMEOUT', 60))
        self.available = self._check_availability()

        if self.available:
            print(f"🤖 AI Service ready: {self.model}")
        else:
            print("⚠️ AI Service unavailable (GROQ_API_KEY not set or invalid)")

    def _check_availability(self):
        """Check if Groq API is available"""
        if not self.api_key:
            return False
        try:
            import requests
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            response = requests.get(
                "https://api.groq.com/openai/v1/models",
                headers=headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"⚠️ Groq API check failed: {e}")
            return False

    def analyze_findings(self, findings, language, context=None):
        """Analyze vulnerabilities using Groq API"""
        if not findings:
            return self._empty_result()

        if not self.available:
            print("⚠️ Groq API unavailable - using fallback")
            return self._fallback_result(findings)

        try:
            prompt = self._build_prompt(findings, language, context)
            raw_response = self._call_groq(prompt)

            if raw_response and not raw_response.startswith('Error:'):
                print(f"📝 Raw response (first 500 chars): {raw_response[:500]}...")
                
                parsed = self._parse_response(raw_response)
                if parsed and 'findings' in parsed and 'summary' in parsed:
                    parsed['summary'] = self._recompute_summary(parsed['findings'], len(findings))
                    print("✅ Real AI analysis complete!")
                    print(f"📊 AI Response length: {len(json.dumps(parsed))} chars")
                    return parsed
                else:
                    print("⚠️ Failed to parse Groq response - using structured fallback")
                    return self._generate_structured_fallback(findings)
            else:
                print("⚠️ Groq call failed - using fallback")
                return self._fallback_result(findings)

        except Exception as e:
            print(f"❌ Groq analysis error: {e}")
            return self._fallback_result(findings)

    def _generate_structured_fallback(self, findings):
        """Generate structured AI-like response based on finding types"""
        ai_findings = []
        
        # Define CVSS scores and remediation templates based on vulnerability type
        vuln_templates = {
            'command_injection': {
                'cvss': 9.8,
                'priority': 'Critical',
                'remediation': 'BAD: system(user_input); FIX: Use execve() with validated arguments and avoid shell=True. ALWAYS: Never pass unsanitized user input to system commands.',
                'exploitability': 'Attacker can execute arbitrary system commands, leading to complete system compromise.'
            },
            'sql_injection': {
                'cvss': 9.3,
                'priority': 'Critical',
                'remediation': 'BAD: "SELECT * FROM users WHERE id = " + user_input; FIX: Use prepared statements with parameterized queries. ALWAYS: Never concatenate user input into SQL queries.',
                'exploitability': 'Attacker can read, modify, or delete database records.'
            },
            'buffer_overflow': {
                'cvss': 8.8,
                'priority': 'High',
                'remediation': 'BAD: strcpy(buffer, input); FIX: strncpy(buffer, input, sizeof(buffer)-1); buffer[sizeof(buffer)-1] = \'\\0\'; ALWAYS: Use bounds-checking functions and validate input length.',
                'exploitability': 'Attacker can overwrite adjacent memory and potentially execute arbitrary code.'
            },
            'double_free': {
                'cvss': 9.0,
                'priority': 'Critical',
                'remediation': 'BAD: free(ptr); free(ptr); FIX: Set pointer to NULL after freeing: free(ptr); ptr = NULL; ALWAYS: Never free the same pointer twice and set to NULL after freeing.',
                'exploitability': 'Attacker can cause memory corruption leading to arbitrary code execution.'
            },
            'use_after_free': {
                'cvss': 8.9,
                'priority': 'Critical',
                'remediation': 'BAD: free(ptr); strcpy(ptr, input); FIX: Set pointer to NULL after freeing and check before use. ALWAYS: Set freed pointers to NULL and never access them again.',
                'exploitability': 'Attacker can access freed memory, leading to code execution or information disclosure.'
            },
            'hardcoded_password': {
                'cvss': 5.3,
                'priority': 'Medium',
                'remediation': 'BAD: PASSWORD = "admin123"; FIX: Use environment variables or secure vault like HashiCorp Vault. ALWAYS: Never hardcode secrets in source code.',
                'exploitability': 'Attacker with source code access can obtain credentials.'
            },
            'integer_overflow': {
                'cvss': 7.5,
                'priority': 'High',
                'remediation': 'BAD: int result = a * b; FIX: if (a > INT_MAX / b) { handle_overflow(); } ALWAYS: Check for overflow before arithmetic operations.',
                'exploitability': 'Attacker can cause arithmetic overflow leading to unexpected behavior.'
            },
            'division_by_zero': {
                'cvss': 7.5,
                'priority': 'High',
                'remediation': 'BAD: int result = a / b; FIX: if (b != 0) { result = a / b; } ALWAYS: Check denominator before division.',
                'exploitability': 'Attacker can cause application crash via division by zero.'
            },
            'resource_leak': {
                'cvss': 5.5,
                'priority': 'Medium',
                'remediation': 'BAD: FileInputStream fis = new FileInputStream("file"); FIX: Use try-with-resources: try (FileInputStream fis = new FileInputStream("file")) { ... } ALWAYS: Always close resources in finally block or use try-with-resources.',
                'exploitability': 'Attacker can exhaust system resources causing denial of service.'
            }
        }
        
        for i, f in enumerate(findings):
            finding_type = f.get('type', '').lower()
            
            # Try to match type with templates
            template = None
            for key, value in vuln_templates.items():
                if key in finding_type or finding_type in key:
                    template = value
                    break
            
            if template:
                ai_findings.append({
                    "id": i,
                    "cvss_score": template['cvss'],
                    "priority": template['priority'],
                    "remediation": template['remediation'],
                    "exploitability": template['exploitability']
                })
            else:
                # Generic template
                severity = f.get('severity', 'info')
                severity_map = {'critical': 9.0, 'high': 7.5, 'medium': 5.0, 'low': 3.0, 'info': 1.0}
                priority_map = {'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low', 'info': 'Info'}
                
                ai_findings.append({
                    "id": i,
                    "cvss_score": severity_map.get(severity, 5.0),
                    "priority": priority_map.get(severity, 'Medium'),
                    "remediation": f"BAD: Vulnerability detected in code. FIX: Review the code and apply appropriate security measures. ALWAYS: Follow security best practices for {finding_type}.",
                    "exploitability": f"Review the vulnerability type: {finding_type}."
                })

        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in ai_findings:
            p = f.get('priority', '').lower()
            if p in counts:
                counts[p] += 1

        return {
            "findings": ai_findings,
            "summary": {
                "critical_count": counts['critical'],
                "high_count": counts['high'],
                "medium_count": counts['medium'],
                "low_count": counts['low'],
                "total": len(findings),
                "overall_priority": f"Address {max(counts, key=counts.get)} severity findings first." if any(counts.values()) else "Review all findings."
            }
        }

    def _build_prompt(self, findings, language, context):
        """Build the prompt for Groq API with specific format"""
        findings_json = []
        for f in findings[:15]:
            findings_json.append({
                "type": f.get('type', f.get('rule_id', 'unknown')),
                "severity": f.get('severity', 'info'),
                "message": (f.get('message', '') or '')[:300],
                "line": f.get('line', 0),
                "code_snippet": (f.get('code_snippet', '') or '')[:200],
                "tool": f.get('tool', 'unknown')
            })

        prompt = f"""You are a senior security expert. Analyze these vulnerabilities and provide expert guidance.

Language: {language}
Context: {context or 'General application'}

Vulnerabilities found:
{json.dumps(findings_json, indent=2)}

For EACH vulnerability, provide:
1. CVSS v3.1 base score (0.0-10.0)
2. Priority: "Critical", "High", "Medium", or "Low"
3. Remediation: Use this EXACT format:
   "BAD: <vulnerable code pattern>; FIX: <secure code pattern>; ALWAYS: <best practice rule>."

4. Exploitability: One sentence describing realistic impact.

IMPORTANT: Keep responses concise and use the BAD/FIX/ALWAYS format.

Respond with ONLY valid JSON, no other text, no markdown.

Example response:
{{
  "findings": [
    {{
      "id": 0,
      "cvss_score": 9.8,
      "priority": "Critical",
      "remediation": "BAD: system(user_input); FIX: execve(validated_args); ALWAYS: Never pass user input to system() without sanitization.",
      "exploitability": "Attacker can execute arbitrary commands on the server."
    }}
  ],
  "summary": {{
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "total": 0,
    "overall_priority": "Address critical and high severity findings first."
  }}
}}"""
        return prompt

    def _call_groq(self, prompt):
        """Call Groq API using requests directly"""
        start_time = time.time()
        try:
            import requests

            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You are a security expert. Respond only with valid JSON. Use the BAD/FIX/ALWAYS format for remediation."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.1,
                "max_tokens": 2048
            }

            response = requests.post(url, headers=headers, json=payload, timeout=self.timeout)

            elapsed = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                response_text = data['choices'][0]['message']['content']
                print(f"✅ Groq call took {elapsed:.1f}s, response length {len(response_text)} chars")
                logger.info(f"Groq call took {elapsed:.1f}s, response length {len(response_text)} chars")
                return response_text
            else:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                print(f"❌ Groq API error: {error_msg}")
                logger.error(f"Groq API error: {error_msg}")
                return f"Error: {error_msg}"

        except requests.exceptions.Timeout:
            elapsed = time.time() - start_time
            print(f"❌ Groq call timed out after {elapsed:.1f}s")
            return "Error: Timeout"

        except Exception as e:
            elapsed = time.time() - start_time
            print(f"❌ Groq call failed after {elapsed:.1f}s: {str(e)}")
            logger.error(f"Groq API error: {str(e)}")
            return f"Error: {str(e)}"

    def _parse_response(self, response):
        """Extract the JSON object from the response"""
        text = response.strip()
        text = re.sub(r'^```(?:json)?\s*|\s*```$', '', text, flags=re.MULTILINE)

        start = text.find('{')
        if start == -1:
            return None

        depth = 0
        for i in range(start, len(text)):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i+1])
                    except:
                        # Try to fix common issues
                        try:
                            fixed = text[start:i+1]
                            fixed = re.sub(r',\s*}', '}', fixed)
                            fixed = re.sub(r',\s*]', ']', fixed)
                            return json.loads(fixed)
                        except:
                            return None
        return None

    def _recompute_summary(self, ai_findings, total_findings):
        """Recompute summary from AI findings"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        highest = None

        for f in ai_findings:
            p = str(f.get('priority', '')).lower()
            if p in counts:
                counts[p] += 1
                if highest is None or p == 'critical' or (p == 'high' and highest != 'critical'):
                    highest = p

        priority_text = f"Address {highest} severity findings first." if highest else "Review findings by severity."

        return {
            "critical_count": counts['critical'],
            "high_count": counts['high'],
            "medium_count": counts['medium'],
            "low_count": counts['low'],
            "total": total_findings,
            "overall_priority": priority_text
        }

    def _fallback_result(self, findings):
        """Fallback when Groq API is unavailable"""
        return self._generate_structured_fallback(findings)

    def _empty_result(self):
        return {
            "findings": [],
            "summary": {
                "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
                "total": 0, "overall_priority": "No vulnerabilities found"
            }
        }
