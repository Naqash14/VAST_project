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
        if not self.api_key:
            return False
        try:
            from groq import Groq
            client = Groq(api_key=self.api_key)
            models = client.models.list()
            return True
        except Exception as e:
            print(f"⚠️ Groq API check failed: {e}")
            return False

    def analyze_findings(self, findings, language, context=None):
        if not findings:
            return self._empty_result()

        if not self.available:
            print("⚠️ Groq API unavailable - using fallback")
            return self._fallback_result(findings)

        try:
            prompt = self._build_prompt(findings, language, context)
            raw_response = self._call_groq(prompt)

            if raw_response and not raw_response.startswith('Error:'):
                parsed = self._parse_response(raw_response)
                if parsed and 'findings' in parsed and 'summary' in parsed:
                    parsed['summary'] = self._recompute_summary(parsed['findings'], len(findings))
                    print("✅ Real AI analysis complete!")
                    print(f"📊 AI Response length: {len(json.dumps(parsed))} chars")
                    return parsed
                else:
                    print("⚠️ Failed to parse Groq response")
                    return self._fallback_result(findings)
            else:
                print("⚠️ Groq call failed")
                return self._fallback_result(findings)

        except Exception as e:
            print(f"❌ Groq analysis error: {e}")
            return self._fallback_result(findings)

    def _build_prompt(self, findings, language, context):
        findings_json = []
        for f in findings:
            findings_json.append({
                "type": f.get('type', f.get('rule_id', 'unknown')),
                "severity": f.get('severity', 'info'),
                "message": f.get('message', 'No message'),
                "line": f.get('line', 0),
                "code_snippet": f.get('code_snippet', ''),
                "tool": f.get('tool', 'unknown')
            })

        prompt = f"""You are a senior security expert. Analyze these vulnerabilities and provide:

1. CVSS v3.1 base score (0.0-10.0)
2. Priority: "Critical", "High", "Medium", or "Low"
3. Remediation: EXACT CODE FIX - Show the line that needs to be changed, and what to change it to. Example format:
   - BAD: os.system(user_input)
   - FIX: subprocess.run(user_input.split(), shell=False)
   - Always provide the exact code line fix!
4. Exploitability: Brief note (1 sentence)

Language: {language}
Context: {context or 'General application'}

Vulnerabilities found:
{json.dumps(findings_json, indent=2)}

IMPORTANT: For remediation, always provide EXACT CODE FIX with before/after examples.

Respond with ONLY valid JSON:
{{
  "findings": [
    {{
      "id": 0,
      "cvss_score": 9.8,
      "priority": "Critical",
      "remediation": "BAD: os.system(user_input)\\nFIX: subprocess.run([user_input], shell=False, capture_output=True)\\nALWAYS validate and sanitize user input.",
      "exploitability": "Brief note"
    }}
  ],
  "summary": {{
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "total": 0,
    "overall_priority": "Summary here"
  }}
}}"""
        return prompt

    def _call_groq(self, prompt):
        start_time = time.time()
        try:
            from groq import Groq

            client = Groq(api_key=self.api_key)

            chat_completion = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You are a security expert. Always provide EXACT CODE FIXES with before/after examples. Be concise but specific."},
                    {"role": "user", "content": prompt}
                ],
                model=self.model,
                temperature=0.1,
                max_tokens=2048,
                timeout=self.timeout
            )

            elapsed = time.time() - start_time
            response_text = chat_completion.choices[0].message.content
            print(f"✅ Groq call took {elapsed:.1f}s, response length {len(response_text)} chars")
            logger.info(f"Groq call took {elapsed:.1f}s, response length {len(response_text)} chars")
            return response_text

        except Exception as e:
            elapsed = time.time() - start_time
            print(f"❌ Groq call failed after {elapsed:.1f}s: {str(e)}")
            logger.error(f"Groq API error: {str(e)}")
            return f"Error: {str(e)}"

    def _parse_response(self, response):
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
                        return None
        return None

    def _recompute_summary(self, ai_findings, total_findings):
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
        severity_score = {'critical': 9.0, 'high': 7.0, 'medium': 5.0, 'low': 3.0, 'info': 1.0}

        ai_findings = []
        for i, f in enumerate(findings):
            severity = f.get('severity', 'info')
            ai_findings.append({
                "id": i,
                "cvss_score": severity_score.get(severity, 1.0),
                "priority": severity.capitalize(),
                "remediation": "AI unavailable. Review manually.",
                "exploitability": "AI unavailable.",
                "is_fallback": True
            })

        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in findings:
            sev = f.get('severity', 'info')
            if sev in counts:
                counts[sev] += 1

        return {
            "findings": ai_findings,
            "summary": {
                "critical_count": counts['critical'],
                "high_count": counts['high'],
                "medium_count": counts['medium'],
                "low_count": counts['low'],
                "total": len(findings),
                "overall_priority": "AI unavailable. Fix critical/high first.",
                "is_fallback": True
            }
        }

    def _empty_result(self):
        return {
            "findings": [],
            "summary": {
                "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
                "total": 0, "overall_priority": "No vulnerabilities found"
            }
        }
