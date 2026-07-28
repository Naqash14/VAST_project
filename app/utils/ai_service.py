"""
AI-Assisted Vulnerability Analysis Service
Uses Groq API for fast, cloud-based LLM analysis
"""

import json
import os
import re
import time
import logging

logger = logging.getLogger(__name__)


class AIPrioritizer:
    """AI-powered vulnerability analysis using Groq API."""

    def __init__(self, model=None):
        # Directly read from environment
        self.api_key = os.environ.get('GROQ_API_KEY')
        self.model = model or os.environ.get('GROQ_MODEL', 'llama-3.3-70b-versatile')
        self.timeout = int(os.environ.get('AI_TIMEOUT', 60))
        self.available = self._check_availability()

        if self.available:
            print(f"🤖 AI Service ready: {self.model}")
        else:
            print(f"⚠️ AI Service unavailable")

    def _check_availability(self):
        """Check if Groq API is available"""
        if not self.api_key:
            print("⚠️ No GROQ_API_KEY found in environment")
            return False
        try:
            from groq import Groq
            client = Groq(api_key=self.api_key)
            # Test the API key
            models = client.models.list()
            print("✅ Groq API connection successful")
            return True
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
                parsed = self._parse_response(raw_response)
                if parsed and 'findings' in parsed and 'summary' in parsed:
                    parsed['summary'] = self._recompute_summary(parsed['findings'], len(findings))
                    print("✅ Real AI analysis complete!")
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
        for f in findings[:15]:
            findings_json.append({
                "type": f.get('type', f.get('rule_id', 'unknown')),
                "severity": f.get('severity', 'info'),
                "message": f.get('message', 'No message'),
                "line": f.get('line', 0),
                "code_snippet": f.get('code_snippet', ''),
                "tool": f.get('tool', 'unknown')
            })

        prompt = f"""You are a senior security expert. Analyze these vulnerabilities.

Language: {language}
Context: {context or 'General application'}

Vulnerabilities:
{json.dumps(findings_json, indent=2)}

For each vulnerability provide:
1. CVSS score (0-10)
2. Priority: Critical/High/Medium/Low
3. Remediation (specific fix)
4. Exploitability (impact note)

Respond with ONLY valid JSON:
{{
  "findings": [
    {{"id": 0, "cvss_score": 7.5, "priority": "High", "remediation": "fix", "exploitability": "impact"}}
  ],
  "summary": {{
    "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
    "total": 0, "overall_priority": "summary"
  }}
}}"""
        return prompt

    def _call_groq(self, prompt):
        start_time = time.time()
        try:
            from groq import Groq

            if not self.api_key:
                return "Error: No API key"

            client = Groq(api_key=self.api_key)

            chat_completion = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You are a security expert. Respond with valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                model=self.model,
                temperature=0.1,
                max_tokens=2000,
                timeout=self.timeout
            )

            elapsed = time.time() - start_time
            response_text = chat_completion.choices[0].message.content
            print(f"✅ Groq call took {elapsed:.1f}s")
            return response_text

        except Exception as e:
            elapsed = time.time() - start_time
            print(f"❌ Groq call failed after {elapsed:.1f}s: {str(e)}")
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

        return {
            "critical_count": counts['critical'],
            "high_count": counts['high'],
            "medium_count": counts['medium'],
            "low_count": counts['low'],
            "total": total_findings,
            "overall_priority": f"Address {highest} severity findings first." if highest else "Review findings by severity."
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
