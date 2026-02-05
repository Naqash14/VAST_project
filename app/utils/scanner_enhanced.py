import subprocess
import json
import tempfile
import os
import re

class EnhancedScanner:
    """Enhanced scanner that's more aggressive for Python/C scanning"""
    
    @staticmethod
    def scan_code(code_content, filename=None):
        """Scan code with multiple strategies"""
        try:
            # Detect language from content
            language = EnhancedScanner._detect_language(code_content, filename)
            print(f"DEBUG: Detected language: {language}")
            
            # Create temp file
            suffix = EnhancedScanner._get_suffix(language)
            with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
                f.write(code_content)
                temp_file = f.name
            
            print(f"DEBUG: Created temp file: {temp_file}")
            
            # Strategy 1: Run multiple semgrep commands
            all_results = []
            
            # For Python, try these configs in order
            if language == 'python':
                configs = [
                    ('auto', 'Auto configuration'),
                    ('p/security-audit', 'Security audit'),
                    ('p/python', 'Python rules'),
                    ('p/secrets', 'Secret detection'),
                    ('p/command-injection', 'Command injection'),
                    ('p/sql-injection', 'SQL injection')
                ]
            elif language == 'c' or language == 'cpp':
                configs = [
                    ('auto', 'Auto configuration'),
                    ('p/c', 'C rules'),
                    ('p/cpp', 'C++ rules'),
                    ('p/security-audit', 'Security audit')
                ]
            else:
                configs = [
                    ('auto', 'Auto configuration'),
                    ('p/security-audit', 'Security audit')
                ]
            
            for config, config_name in configs:
                print(f"DEBUG: Trying config: {config_name}")
                results = EnhancedScanner._run_semgrep_config(temp_file, config)
                if results and 'results' in results:
                    all_results.extend(results['results'])
                    print(f"DEBUG: {config_name} found {len(results['results'])} issues")
            
            # Strategy 2: Run with --pattern for common vulnerabilities
            if language == 'python' and not all_results:
                print("DEBUG: Trying pattern-based scanning for Python...")
                patterns = [
                    ("os.system($X)", "command injection"),
                    ("subprocess.call($X, shell=True)", "command injection"),
                    ("pickle.loads($X)", "insecure deserialization"),
                    ("eval($X)", "code injection"),
                    ("exec($X)", "code injection"),
                    ("f\"SELECT.*{ $X }\"", "SQL injection"),
                    ("\"SELECT.*\" + $X", "SQL injection"),
                    ("cursor.execute($X)", "potential SQL injection"),
                    ("PASSWORD = \"", "hardcoded password"),
                    ("password = \"", "hardcoded password"),
                    ("api_key = \"", "hardcoded API key"),
                    ("secret = \"", "hardcoded secret")
                ]
                
                for pattern, description in patterns:
                    results = EnhancedScanner._run_semgrep_pattern(temp_file, pattern, language, description)
                    if results and 'results' in results:
                        all_results.extend(results['results'])
                        print(f"DEBUG: Pattern '{pattern}' found {len(results['results'])} issues")
            
            # Strategy 3: Manual pattern matching for Python if semgrep fails
            if language == 'python' and not all_results:
                print("DEBUG: Manual pattern checking...")
                manual_findings = EnhancedScanner._manual_python_check(code_content)
                if manual_findings:
                    all_results.extend(manual_findings)
                    print(f"DEBUG: Manual check found {len(manual_findings)} issues")
            
            # Clean up
            os.unlink(temp_file)
            
            # Remove duplicates
            unique_results = []
            seen = set()
            for result in all_results:
                if isinstance(result, dict) and 'check_id' in result:
                    key = f"{result.get('check_id', '')}:{result.get('start', {}).get('line', 0)}"
                else:
                    key = str(result)
                
                if key not in seen:
                    seen.add(key)
                    unique_results.append(result)
            
            print(f"DEBUG: Total unique findings: {len(unique_results)}")
            
            # Process results
            return EnhancedScanner._process_results({'results': unique_results}, language)
            
        except Exception as e:
            print(f"DEBUG: Error in scan_code: {str(e)}")
            import traceback
            traceback.print_exc()
            return {"error": str(e), "by_severity": {}, "details": [], "total_findings": 0}
    
    @staticmethod
    def _detect_language(content, filename):
        """Detect programming language from content and filename"""
        if filename:
            ext = os.path.splitext(filename)[1].lower()
            ext_map = {
                '.py': 'python',
                '.c': 'c',
                '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp',
                '.h': 'c', '.hpp': 'cpp',
                '.java': 'java',
                '.js': 'javascript', '.jsx': 'javascript',
                '.ts': 'typescript', '.tsx': 'typescript',
                '.php': 'php',
                '.rb': 'ruby',
                '.go': 'go',
                '.rs': 'rust'
            }
            if ext in ext_map:
                return ext_map[ext]
        
        # Detect from content
        content_lower = content.lower()
        if 'import sqlite3' in content or 'def ' in content and ':' in content:
            return 'python'
        elif '#include' in content and ('int main' in content or 'void main' in content):
            return 'c'
        elif 'public class' in content or 'import java.' in content:
            return 'java'
        elif '<?php' in content:
            return 'php'
        elif 'function ' in content or 'console.log' in content:
            return 'javascript'
        elif 'package main' in content or 'func ' in content:
            return 'go'
        else:
            return 'python'  # Default
    
    @staticmethod
    def _get_suffix(language):
        """Get file suffix for language"""
        suffix_map = {
            'python': '.py',
            'c': '.c',
            'cpp': '.cpp',
            'java': '.java',
            'javascript': '.js',
            'php': '.php',
            'ruby': '.rb',
            'go': '.go',
            'rust': '.rs'
        }
        return suffix_map.get(language, '.txt')
    
    @staticmethod
    def _run_semgrep_config(file_path, config, timeout=20):
        """Run semgrep with specific config"""
        try:
            cmd = ['semgrep', 'scan', '--config', config, '--json', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode in [0, 2]:  # 0 = success, 2 = findings
                if result.stdout.strip():
                    return json.loads(result.stdout)
                else:
                    return {"results": []}
            else:
                print(f"DEBUG: Semgrep error (code {result.returncode}) with config {config}")
                return None
                
        except Exception as e:
            print(f"DEBUG: Error with config {config}: {str(e)}")
            return None
    
    @staticmethod
    def _run_semgrep_pattern(file_path, pattern, language, description):
        """Run semgrep with specific pattern"""
        try:
            cmd = ['semgrep', '-e', pattern, '-l', language, '--json', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode in [0, 2]:
                if result.stdout.strip():
                    data = json.loads(result.stdout)
                    # Add description to findings
                    if 'results' in data:
                        for finding in data['results']:
                            if 'extra' in finding and 'message' in finding['extra']:
                                finding['extra']['message'] = f"{description}: {finding['extra']['message']}"
                    return data
                else:
                    return {"results": []}
            else:
                return None
                
        except Exception as e:
            print(f"DEBUG: Error with pattern {pattern}: {str(e)}")
            return None
    
    @staticmethod
    def _manual_python_check(content):
        """Manual check for Python vulnerabilities if semgrep fails"""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Check for SQL injection patterns
            if 'cursor.execute(' in line and ('+' in line or 'f"' in line or 'format(' in line):
                if '?' not in line and '%s' not in line:  # Not using parameterized queries
                    findings.append({
                        'check_id': 'manual.sql-injection',
                        'path': 'manual_check',
                        'start': {'line': i, 'col': 0},
                        'end': {'line': i, 'col': len(line)},
                        'extra': {
                            'message': 'Potential SQL injection: String concatenation in SQL query',
                            'severity': 'HIGH',
                            'lines': line_stripped
                        }
                    })
            
            # Check for command injection
            if any(cmd in line for cmd in ['os.system(', 'subprocess.call(', 'subprocess.run(', 'os.popen(']):
                if '+' in line or 'f"' in line or 'format(' in line:
                    findings.append({
                        'check_id': 'manual.command-injection',
                        'path': 'manual_check',
                        'start': {'line': i, 'col': 0},
                        'end': {'line': i, 'col': len(line)},
                        'extra': {
                            'message': 'Potential command injection: User input in shell command',
                            'severity': 'HIGH',
                            'lines': line_stripped
                        }
                    })
            
            # Check for hardcoded secrets
            if any(keyword in line.lower() for keyword in ['password', 'api_key', 'secret', 'token', 'key']):
                if '="' in line or "='" in line or '="' in line or "='" in line:
                    # Check if it's an assignment with a string literal
                    if '=' in line and ('"' in line or "'" in line):
                        findings.append({
                            'check_id': 'manual.hardcoded-secret',
                            'path': 'manual_check',
                            'start': {'line': i, 'col': 0},
                            'end': {'line': i, 'col': len(line)},
                            'extra': {
                                'message': 'Potential hardcoded secret',
                                'severity': 'MEDIUM',
                                'lines': line_stripped
                            }
                        })
            
            # Check for eval/exec
            if 'eval(' in line or 'exec(' in line:
                findings.append({
                    'check_id': 'manual.code-injection',
                    'path': 'manual_check',
                    'start': {'line': i, 'col': 0},
                    'end': {'line': i, 'col': len(line)},
                    'extra': {
                        'message': 'Use of eval/exec can lead to code injection',
                        'severity': 'HIGH',
                        'lines': line_stripped
                    }
                })
        
        return findings
    
    @staticmethod
    def _process_results(results_data, language):
        """Process results"""
        processed = {
            "total_findings": 0,
            "by_severity": {
                "critical": 0, 
                "high": 0, 
                "medium": 0, 
                "low": 0, 
                "info": 0
            },
            "details": []
        }
        
        if 'results' in results_data:
            for finding in results_data['results']:
                # Handle both semgrep format and manual format
                if isinstance(finding, dict):
                    severity = finding.get('extra', {}).get('severity', 'info').lower()
                    
                    # Normalize severity
                    if severity == 'warning':
                        severity = 'medium'
                    elif severity == 'error':
                        severity = 'high'
                    
                    if severity not in processed["by_severity"]:
                        severity = 'info'
                    
                    processed["by_severity"][severity] += 1
                    processed["total_findings"] += 1
                    
                    # Extract information
                    message = finding.get('extra', {}).get('message', 'No message')
                    rule_id = finding.get('check_id', 'manual.unknown')
                    line = finding.get('start', {}).get('line', 0)
                    
                    # Get code snippet
                    code_snippet = ""
                    if 'extra' in finding and 'lines' in finding['extra']:
                        code_snippet = finding['extra']['lines']
                    elif 'extra' in finding and isinstance(finding['extra'], dict) and 'lines' in finding['extra']:
                        code_snippet = finding['extra']['lines']
                    
                    # Categorize
                    finding_type = 'other'
                    rule_lower = rule_id.lower()
                    
                    if any(x in rule_lower for x in ['sql', 'injection', 'execute']):
                        finding_type = 'sql_injection'
                    elif any(x in rule_lower for x in ['command', 'exec', 'shell', 'system', 'popen']):
                        finding_type = 'command_injection'
                    elif any(x in rule_lower for x in ['xss', 'cross-site', 'html']):
                        finding_type = 'xss'
                    elif any(x in rule_lower for x in ['buffer', 'overflow', 'strcpy', 'gets']):
                        finding_type = 'buffer_overflow'
                    elif any(x in rule_lower for x in ['password', 'secret', 'key', 'credential', 'hardcoded']):
                        finding_type = 'hardcoded_secret'
                    elif any(x in rule_lower for x in ['eval', 'exec', 'code-injection']):
                        finding_type = 'code_injection'
                    elif any(x in rule_lower for x in ['pickle', 'yaml', 'deserialization']):
                        finding_type = 'insecure_deserialization'
                    
                    processed["details"].append({
                        "severity": severity,
                        "message": message,
                        "rule_id": rule_id,
                        "line": line,
                        "code_snippet": code_snippet,
                        "type": finding_type
                    })
        
        return processed
    
    @staticmethod
    def scan_file(file_path):
        """Scan uploaded file"""
        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}", "by_severity": {}, "details": [], "total_findings": 0}
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return EnhancedScanner.scan_code(content, os.path.basename(file_path))
            
        except Exception as e:
            print(f"DEBUG: File scan error: {str(e)}")
            return {"error": str(e), "by_severity": {}, "details": [], "total_findings": 0}

# Test
def test_enhanced_scanner():
    print("Testing EnhancedScanner...")
    
    # Test Python code that should find vulnerabilities
    test_code = """import sqlite3
import os
import pickle

def sql_injection(user_id):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # SQL injection
    return cursor.fetchone()

def command_injection(cmd):
    os.system("ping " + cmd)  # Command injection

def dangerous_eval(code):
    return eval(code)  # Code injection

PASSWORD = "admin123"  # Hardcoded password

data = pickle.loads(user_input)  # Insecure deserialization
"""
    
    results = EnhancedScanner.scan_code(test_code, 'test.py')
    
    print(f"\nResults for Python code:")
    print(f"Total findings: {results.get('total_findings', 0)}")
    print(f"By severity: {results.get('by_severity', {})}")
    
    if results.get('details'):
        for i, finding in enumerate(results['details'], 1):
            print(f"\n{i}. [{finding['severity'].upper()}] {finding['rule_id']}")
            print(f"   Line {finding['line']}: {finding['message']}")

if __name__ == "__main__":
    test_enhanced_scanner()
