import os
import json
import requests
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class AIAnalyzer:
    def __init__(self):
        self.api_key = os.environ.get('GROQ_API_KEY')
        self.model = os.environ.get('GROQ_MODEL', 'llama-3.3-70b-versatile')
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        self.timeout = int(os.environ.get('AI_TIMEOUT', 60))
        
    def analyze_vulnerabilities(self, findings, code_content=None):
        """Analyze vulnerabilities using Groq AI"""
        if not self.api_key:
            logger.error("GROQ_API_KEY not configured")
            return {
                "error": "AI API key not configured",
                "summary": "AI analysis unavailable. Please configure GROQ_API_KEY.",
                "recommendations": ["Configure GROQ_API_KEY in environment variables"]
            }
        
        try:
            # Prepare the prompt
            prompt = self._build_prompt(findings, code_content)
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You are a security expert analyzing code vulnerabilities. Provide detailed, actionable recommendations."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 1000
            }
            
            logger.info(f"Sending AI analysis request to Groq API")
            
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                ai_response = result.get('choices', [{}])[0].get('message', {}).get('content', '')
                logger.info("AI analysis completed successfully")
                
                return {
                    "success": True,
                    "analysis": ai_response,
                    "summary": self._extract_summary(ai_response),
                    "recommendations": self._extract_recommendations(ai_response)
                }
            else:
                logger.error(f"Groq API error: {response.status_code} - {response.text}")
                return {
                    "error": f"API error: {response.status_code}",
                    "summary": "AI analysis failed",
                    "recommendations": ["Check API key and try again"]
                }
                
        except requests.Timeout:
            logger.error("Groq API timeout")
            return {
                "error": "API timeout",
                "summary": "AI analysis timed out",
                "recommendations": ["Try again later or check API availability"]
            }
        except Exception as e:
            logger.error(f"AI analysis error: {str(e)}")
            return {
                "error": str(e),
                "summary": "AI analysis failed",
                "recommendations": ["Check logs for details"]
            }
    
    def _build_prompt(self, findings, code_content=None):
        """Build the prompt for AI analysis"""
        prompt = "Analyze the following code vulnerabilities and provide:\n"
        prompt += "1. A brief summary of the security issues\n"
        prompt += "2. Specific recommendations to fix each vulnerability\n"
        prompt += "3. Priority order for fixing (critical first)\n\n"
        
        if findings:
            prompt += "Vulnerabilities found:\n"
            for finding in findings:
                prompt += f"- {finding}\n"
        
        if code_content:
            prompt += f"\nCode snippet:\n{code_content[:500]}...\n"
        
        return prompt
    
    def _extract_summary(self, response):
        """Extract summary from AI response"""
        lines = response.split('\n')
        for line in lines:
            if 'summary' in line.lower() or 'overview' in line.lower():
                return line.replace('Summary:', '').replace('Overview:', '').strip()
        return response[:200] + "..." if len(response) > 200 else response
    
    def _extract_recommendations(self, response):
        """Extract recommendations from AI response"""
        recommendations = []
        lines = response.split('\n')
        for line in lines:
            if any(x in line.lower() for x in ['recommend', 'fix', 'should', 'consider']):
                clean_line = line.strip()
                if clean_line and len(clean_line) > 10:
                    recommendations.append(clean_line)
        return recommendations[:5]  # Return top 5 recommendations

# Singleton instance
_ai_analyzer = None

def get_ai_analyzer():
    global _ai_analyzer
    if _ai_analyzer is None:
        _ai_analyzer = AIAnalyzer()
    return _ai_analyzer
