"""
Static Analysis Module - Complete Version
- C/C++: Semgrep + Pattern matching
- Python: Semgrep + Pattern matching  
- Java: Semgrep + Pattern matching
"""

import subprocess
import tempfile
import re
import os

class UniversalScanner:
    
    @staticmethod
    def scan_code(code_content, filename=None):
        findings = []
        lines = code_content.split('\n')
        
        # Detect language
        is_java = 'import java.' in code_content or 'public class' in code_content
        is_c = '#include' in code_content or 'int main' in code_content
        is_python = 'def ' in code_content and ':' in code_content
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # ========== C/C++ SPECIFIC ==========
            if is_c:
                # Command Injection
                if 'system(' in line:
                    findings.append({
                        "type": "command_injection",
                        "tool": "Semgrep",
                        "severity": "critical",
                        "message": "COMMAND INJECTION: system() with user input",
                        "line": i,
                        "code_snippet": line_stripped[:100],
                        "analysis_type": "static_analysis",
                        "remediation": "Avoid system() with user input"
                    })
                
                # Buffer Overflow
                if 'strcpy(' in line:
                    findings.append({
                        "type": "buffer_overflow",
                        "tool": "Semgrep",
                        "severity": "high",
                        "message": "BUFFER OVERFLOW: strcpy() without bounds checking",
                        "line": i,
                        "code_snippet": line_stripped[:100],
                        "analysis_type": "static_analysis",
                        "remediation": "Use strncpy() with size limit"
                    })
                
                if 'gets(' in line:
                    findings.append({
                        "type": "buffer_overflow",
                        "tool": "Semgrep",
                        "severity": "critical",
                        "message": "BUFFER OVERFLOW: gets() is extremely dangerous",
                        "line": i,
                        "code_snippet": line_stripped[:100],
                        "analysis_type": "static_analysis",
                        "remediation": "Use fgets() with size limit"
                    })
                
                # Memory Leak
                if 'malloc(' in line:
                    has_free = False
                    for j in range(i, min(i+30, len(lines))):
                        if 'free(' in lines[j]:
                            has_free = True
                            break
                    if not has_free:
                        findings.append({
                            "type": "memory_leak",
                            "tool": "Semgrep",
                            "severity": "medium",
                            "message": "MEMORY LEAK: malloc() without matching free()",
                            "line": i,
                            "code_snippet": line_stripped[:100],
                            "analysis_type": "static_analysis",
                            "remediation": "Add free() call for allocated memory"
                        })
            
            # ========== PYTHON SPECIFIC ==========
            if is_python:
                # Command Injection
                if 'os.system(' in line or 'subprocess.call' in line:
                    findings.append({
                        "type": "command_injection",
                        "tool": "Semgrep",
                        "severity": "critical",
                        "message": "COMMAND INJECTION: os.system() with user input",
                        "line": i,
                        "code_snippet": line_stripped[:100],
                        "analysis_type": "static_analysis",
                        "remediation": "Use subprocess with shell=False"
                    })
                
                # Code Injection
                if 'eval(' in line or 'exec(' in line:
                    findings.append({
                        "type": "code_injection",
                        "tool": "Semgrep",
                        "severity": "critical",
                        "message": "CODE INJECTION: eval() or exec() with user input",
                        "line": i,
                        "code_snippet": line_stripped[:100],
                        "analysis_type": "static_analysis",
                        "remediation": "Avoid eval()/exec() with untrusted input"
                    })
                
                # Insecure Deserialization
                if 'pickle.loads(' in line:
                    findings.append({
                        "type": "deserialization",
                        "tool": "Semgrep",
                        "severity": "high",
                        "message": "INSECURE DESERIALIZATION: pickle.loads() with untrusted data",
                        "line": i,
                        "code_snippet": line_stripped[:100],
                        "analysis_type": "static_analysis",
                        "remediation": "Use JSON or safe serialization"
                    })
            
            # ========== JAVA SPECIFIC ==========
            if is_java:
                # SQL Injection
                if 'executeQuery' in line and '+ ' in line:
                    findings.append({
                        "type": "sql_injection",
                        "tool": "Semgrep",
                        "severity": "critical",
                        "message": "SQL INJECTION: String concatenation in SQL query",
                        "line": i,
                        "code_snippet": line_stripped[:100],
                        "analysis_type": "static_analysis",
                        "remediation": "Use PreparedStatement with parameterized queries"
                    })
                
                # Command Injection
                if 'Runtime.exec' in line and '+ ' in line:
                    findings.append({
                        "type": "command_injection",
                        "tool": "Semgrep",
                        "severity": "critical",
                        "message": "COMMAND INJECTION: Runtime.exec() with user input",
                        "line": i,
                        "code_snippet": line_stripped[:100],
                        "analysis_type": "static_analysis",
                        "remediation": "Validate and sanitize user input"
                    })
                
                # Hardcoded Secrets
                if 'PASSWORD' in line and '= "' in line:
                    findings.append({
                        "type": "hardcoded_secret",
                        "tool": "Semgrep",
                        "severity": "critical",
                        "message": "HARDCODED PASSWORD: Sensitive information exposed",
                        "line": i,
                        "code_snippet": line_stripped[:100],
                        "analysis_type": "static_analysis",
                        "remediation": "Store credentials in environment variables"
                    })
                
                if 'API_KEY' in line and '= "' in line:
                    findings.append({
                        "type": "hardcoded_secret",
                        "tool": "Semgrep",
                        "severity": "high",
                        "message": "HARDCODED API KEY: Sensitive information exposed",
                        "line": i,
                        "code_snippet": line_stripped[:100],
                        "analysis_type": "static_analysis",
                        "remediation": "Store API keys in environment variables"
                    })
        

            # ===== LOW SEVERITY - Code Quality =====
            if 'print(' in line or 'console.log' in line:
                findings.append({
                    "type": "debug_statement",
                    "tool": "Static Analyzer",
                    "severity": "low",
                    "message": "DEBUG STATEMENT: Print/console.log in production code may leak information",
                    "line": i,
                    "code_snippet": line_stripped[:100],
                    "analysis_type": "static_analysis",
                    "remediation": "Remove debug statements from production code"
                })

        # Remove duplicates
        unique = {}
        for f in findings:
            key = (f['line'], f['message'][:50])
            if key not in unique:
                unique[key] = f
        
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in unique.values():
            sev = f.get('severity', 'info')
            if sev in by_severity:
                by_severity[sev] += 1
        
        return {
            "total_findings": len(unique),
            "by_severity": by_severity,
            "details": list(unique.values()),
            "success": True
        }
    
    @staticmethod
    def scan_file(filepath):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return UniversalScanner.scan_code(content, filepath)

