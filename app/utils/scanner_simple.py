import json
import random
from datetime import datetime
import os

class CodeScanner:
    def __init__(self, upload_folder):
        self.upload_folder = upload_folder
    
    def scan_with_semgrep(self, code_content, filename=None):
        """Mock scanner for testing - returns simulated results"""
        try:
            # Check if code content is empty
            if not code_content or not code_content.strip():
                return {"error": "No code content provided", "by_severity": {}, "details": []}
            
            # Simulate processing time
            import time
            time.sleep(1)  # Simulate 1 second scan
            
            # Generate mock findings based on code content
            findings = self._generate_mock_findings(code_content)
            return findings
            
        except Exception as e:
            return {"error": f"Scan error: {str(e)}", "by_severity": {}, "details": []}
    
    def _generate_mock_findings(self, code_content):
        """Generate realistic mock findings based on code content"""
        vulnerabilities = []
        lines = code_content.split('\n')
        
        # Check for common vulnerabilities
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            # SQL Injection
            if ('execute(' in line and ('f"' in line or 'f\'' in line)) or \
               ('sql' in line_lower and 'f"' in line):
                vulnerabilities.append({
                    'severity': 'high',
                    'message': 'Possible SQL Injection - String formatting in SQL query',
                    'rule_id': 'python.sql-injection',
                    'line': i,
                    'file': 'input.py',
                    'metadata': {'category': 'security', 'confidence': 'high'}
                })
            
            # Command Injection
            if ('os.system' in line or 'subprocess.call' in line or 'subprocess.run' in line) and \
               ('f"' in line or 'f\'' in line or 'input(' in line_lower):
                vulnerabilities.append({
                    'severity': 'critical',
                    'message': 'Possible Command Injection - User input in system command',
                    'rule_id': 'python.command-injection',
                    'line': i,
                    'file': 'input.py',
                    'metadata': {'category': 'security', 'confidence': 'medium'}
                })
            
            # Hardcoded secrets
            if 'password' in line_lower and '=' in line and \
               ('"admin' in line_lower or "'admin" in line_lower or '"123' in line or "'123" in line):
                vulnerabilities.append({
                    'severity': 'medium',
                    'message': 'Hardcoded password detected',
                    'rule_id': 'python.hardcoded-password',
                    'line': i,
                    'file': 'input.py',
                    'metadata': {'category': 'security', 'confidence': 'high'}
                })
            
            # Insecure deserialization
            if 'pickle.loads' in line or 'pickle.load(' in line:
                vulnerabilities.append({
                    'severity': 'high',
                    'message': 'Insecure deserialization - pickle can execute arbitrary code',
                    'rule_id': 'python.insecure-deserialization',
                    'line': i,
                    'file': 'input.py',
                    'metadata': {'category': 'security', 'confidence': 'high'}
                })
            
            # Weak crypto
            if 'hashlib.md5' in line or 'hashlib.sha1' in line:
                vulnerabilities.append({
                    'severity': 'medium',
                    'message': 'Weak cryptographic hash function used',
                    'rule_id': 'python.weak-crypto',
                    'line': i,
                    'file': 'input.py',
                    'metadata': {'category': 'security', 'confidence': 'high'}
                })
        
        # If no vulnerabilities found, add a success message
        if not vulnerabilities:
            return {
                "total_findings": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "details": []
            }
        
        # Count by severity
        severity_counts = {
            "critical": sum(1 for v in vulnerabilities if v['severity'] == 'critical'),
            "high": sum(1 for v in vulnerabilities if v['severity'] == 'high'),
            "medium": sum(1 for v in vulnerabilities if v['severity'] == 'medium'),
            "low": sum(1 for v in vulnerabilities if v['severity'] == 'low'),
            "info": 0
        }
        
        return {
            "total_findings": len(vulnerabilities),
            "by_severity": severity_counts,
            "details": vulnerabilities
        }
    
    def _find_line_number(self, code_content, search_text):
        """Find line number containing search text"""
        lines = code_content.split('\n')
        for i, line in enumerate(lines, 1):
            if search_text in line:
                return i
        return 1
    
    def scan_file(self, file_path):
        """Scan uploaded file"""
        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}", 
                        "by_severity": {}, "details": []}
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            return self.scan_with_semgrep(content)
        except Exception as e:
            return {"error": str(e), "by_severity": {}, "details": []}
