#!/usr/bin/env python3
"""Universal scanner that combines multiple detection methods"""
import subprocess
import json
import tempfile
import os
import re
import time

class UniversalScanner:
    """Scanner that uses multiple techniques to find vulnerabilities"""
    
    @staticmethod
    def scan_code(code_content, filename=None, timeout=30):
        """Scan code using multiple methods"""
        try:
            print(f"\nDEBUG: Starting universal scan...")
            print(f"DEBUG: Code length: {len(code_content)}")
            print(f"DEBUG: Filename: {filename}")
            
            # Create temp file
            suffix = UniversalScanner._get_file_suffix(filename, code_content)
            with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
                f.write(code_content)
                temp_file = f.name
            
            print(f"DEBUG: Created temp file: {temp_file}")
            
            all_results = []
            
            # Method 1: Semgrep with all relevant configs
            semgrep_results = UniversalScanner._run_semgrep_comprehensive(temp_file, suffix)
            all_results.extend(semgrep_results)
            print(f"DEBUG: Semgrep found {len(semgrep_results)} issues")
            
            # Method 2: Pattern matching (for things semgrep might miss)
            pattern_results = UniversalScanner._pattern_match(code_content, suffix)
            all_results.extend(pattern_results)
            print(f"DEBUG: Pattern matching found {len(pattern_results)} issues")
            
            # Method 3: For Python, run additional checks
            if suffix == '.py':
                python_results = UniversalScanner._check_python_specific(code_content)
                all_results.extend(python_results)
                print(f"DEBUG: Python-specific checks found {len(python_results)} issues")
            
            # Method 4: For C/C++, run additional checks
            if suffix in ['.c', '.cpp', '.h']:
                c_results = UniversalScanner._check_c_specific(code_content)
                all_results.extend(c_results)
                print(f"DEBUG: C-specific checks found {len(c_results)} issues")
            
            # Clean up
            os.unlink(temp_file)
            
            # Remove duplicates
            unique_results = UniversalScanner._remove_duplicates(all_results)
            print(f"DEBUG: Total unique findings: {len(unique_results)}")
            
            # Process results
            return UniversalScanner._process_results(unique_results)
            
        except Exception as e:
            print(f"DEBUG: Error in universal scan: {str(e)}")
            import traceback
            traceback.print_exc()
            return {"error": str(e), "by_severity": {}, "details": [], "total_findings": 0}
    
    @staticmethod
    def _get_file_suffix(filename, code_content):
        """Determine file suffix from filename or content"""
        if filename:
            _, ext = os.path.splitext(filename)
            if ext:
                return ext.lower()
        
        # Guess from content
        content_lower = code_content.lower()
        if '<?php' in code_content:
            return '.php'
        elif '#include' in code_content and 'int main' in code_content:
            return '.c'
        elif 'public class' in content_lower:
            return '.java'
        elif 'function ' in content_lower or 'console.log' in content_lower or 'document.' in content_lower:
            return '.js'
        elif 'import ' in content_lower and ('def ' in content_lower or 'class ' in content_lower):
            return '.py'
        elif '<?xml' in code_content or '<html' in content_lower:
            return '.html'
        else:
            return '.txt'
    
    @staticmethod
    def _run_semgrep_comprehensive(file_path, suffix):
        """Run semgrep with multiple configurations"""
        results = []
        configs = []
        
        # Add configs based on file type
        if suffix == '.py':
            configs = ['auto', 'p/python', 'p/security-audit', 'p/secrets']
        elif suffix in ['.c', '.cpp', '.h']:
            configs = ['p/c', 'auto']
        elif suffix == '.java':
            configs = ['p/java', 'auto']
        elif suffix in ['.js', '.jsx', '.ts', '.tsx']:
            configs = ['p/javascript', 'auto']
        elif suffix == '.php':
            configs = ['p/php', 'auto']
        else:
            configs = ['auto']
        
        for config in configs:
            try:
                cmd = ['semgrep', 'scan', '--config', config, '--json', '--metrics', 'off', file_path]
                print(f"DEBUG: Trying semgrep config: {config}")
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                
                if result.returncode in [0, 2] and result.stdout.strip():
                    data = json.loads(result.stdout)
                    if 'results' in data:
                        for finding in data['results']:
                            results.append({
                                'source': 'semgrep',
                                'config': config,
                                'finding': finding
                            })
                        print(f"DEBUG: Config {config} found {len(data['results'])} issues")
                        
            except Exception as e:
                print(f"DEBUG: Error with config {config}: {str(e)}")
                continue
        
        return results
    
    @staticmethod
    def _pattern_match(code_content, suffix):
        """Pattern matching for common vulnerabilities"""
        results = []
        lines = code_content.split('\n')
        
        # SQL Injection patterns
        sql_patterns = [
            (r'execute\s*\([^)]*[\+\'"]\s*\+\s*[a-zA-Z_][a-zA-Z0-9_]*', 'SQL Injection - String concatenation in execute()'),
            (r'cursor\.execute\s*\([^)]*["\']\s*\%', 'SQL Injection - % formatting in SQL'),
            (r'cursor\.execute\s*\([^)]*f["\']', 'SQL Injection - f-string in SQL'),
            (r'SELECT.*FROM.*WHERE.*["\']\s*\+\s*[a-zA-Z_]', 'SQL Injection - String concatenation in WHERE'),
            (r'query\s*=\s*["\'][^"\']*["\']\s*\+\s*[a-zA-Z_]', 'SQL Injection - Query string concatenation'),
        ]
        
        # Command Injection patterns
        cmd_patterns = [
            (r'os\.system\s*\([^)]*[\+\'"]\s*\+\s*[a-zA-Z_]', 'Command Injection - os.system with concatenation'),
            (r'subprocess\.call\([^)]*shell\s*=\s*True', 'Command Injection - subprocess with shell=True'),
            (r'exec\([^)]*[a-zA-Z_][a-zA-Z0-9_]*', 'Command Injection - exec with variable'),
            (r'eval\([^)]*[a-zA-Z_][a-zA-Z0-9_]*', 'Command Injection - eval with variable'),
        ]
        
        # Hardcoded secrets patterns
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']{6,}["\']', 'Hardcoded Password'),
            (r'api_key\s*=\s*["\'][^"\']{8,}["\']', 'Hardcoded API Key'),
            (r'secret\s*=\s*["\'][^"\']{6,}["\']', 'Hardcoded Secret'),
            (r'token\s*=\s*["\'][^"\']{8,}["\']', 'Hardcoded Token'),
            (r'key\s*=\s*["\'](sk_|AKIA|ghp_)[^"\']*["\']', 'Hardcoded Secret Key Pattern'),
        ]
        
        # Buffer overflow patterns (C/C++)
        buffer_patterns = [
            (r'strcpy\s*\([^,]+,\s*[a-zA-Z_]', 'Buffer Overflow - strcpy() with variable'),
            (r'gets\s*\([a-zA-Z_]', 'Buffer Overflow - gets() function'),
            (r'sprintf\s*\([^,]+,\s*[^,]+,\s*[a-zA-Z_]', 'Buffer Overflow - sprintf() with variable'),
            (r'strcat\s*\([^,]+,\s*[a-zA-Z_]', 'Buffer Overflow - strcat() with variable'),
        ]
        
        # Check all patterns
        all_patterns = sql_patterns + cmd_patterns + secret_patterns
        if suffix in ['.c', '.cpp', '.h']:
            all_patterns += buffer_patterns
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                continue
                
            for pattern, message in all_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    results.append({
                        'source': 'pattern',
                        'config': 'regex',
                        'finding': {
                            'check_id': 'pattern_match',
                            'path': 'pattern_match',
                            'start': {'line': i},
                            'end': {'line': i},
                            'extra': {
                                'message': message,
                                'severity': 'high' if 'Injection' in message or 'Overflow' in message else 'medium',
                                'lines': line_stripped
                            }
                        }
                    })
                    break  # Only report first match per line
        
        return results
    
    @staticmethod
    def _check_python_specific(code_content):
        """Python-specific vulnerability checks"""
        results = []
        lines = code_content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Pickle deserialization
            if 'pickle.loads' in line and not line_stripped.startswith('#'):
                results.append({
                    'source': 'python_specific',
                    'config': 'python',
                    'finding': {
                        'check_id': 'python.insecure-deserialization',
                        'path': 'python_check',
                        'start': {'line': i},
                        'end': {'line': i},
                        'extra': {
                            'message': 'Insecure Deserialization - pickle.loads() can lead to RCE',
                            'severity': 'critical',
                            'lines': line_stripped
                        }
                    }
                })
            
            # YAML deserialization
            if 'yaml.load' in line and 'yaml.safe_load' not in line and not line_stripped.startswith('#'):
                results.append({
                    'source': 'python_specific',
                    'config': 'python',
                    'finding': {
                        'check_id': 'python.yaml-deserialization',
                        'path': 'python_check',
                        'start': {'line': i},
                        'end': {'line': i},
                        'extra': {
                            'message': 'Insecure YAML Deserialization - use yaml.safe_load() instead',
                            'severity': 'high',
                            'lines': line_stripped
                        }
                    }
                })
            
            # Debug statements with secrets
            if ('print(' in line or 'logging.' in line) and any(keyword in line.lower() for keyword in ['password', 'secret', 'key', 'token']):
                if not line_stripped.startswith('#'):
                    results.append({
                        'source': 'python_specific',
                        'config': 'python',
                        'finding': {
                            'check_id': 'python.debug-secret',
                            'path': 'python_check',
                            'start': {'line': i},
                            'end': {'line': i},
                            'extra': {
                                'message': 'Debug Statement Exposing Secret - Remove before production',
                                'severity': 'medium',
                                'lines': line_stripped
                            }
                        }
                    })
        
        return results
    
    @staticmethod
    def _check_c_specific(code_content):
        """C/C++ specific vulnerability checks"""
        results = []
        lines = code_content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Memory allocation without checking
            if 'malloc(' in line and 'if (' not in lines[i-2:i+2] and 'if(' not in lines[i-2:i+2]:
                if not line_stripped.startswith('//') and not line_stripped.startswith('/*'):
                    results.append({
                        'source': 'c_specific',
                        'config': 'c',
                        'finding': {
                            'check_id': 'c.unchecked-malloc',
                            'path': 'c_check',
                            'start': {'line': i},
                            'end': {'line': i},
                            'extra': {
                                'message': 'Unchecked malloc() - Always check return value',
                                'severity': 'medium',
                                'lines': line_stripped
                            }
                        }
                    })
            
            # Free without null check
            if 'free(' in line and lines[i-1].strip() != 'if (ptr)' and lines[i-1].strip() != 'if(ptr)':
                if not line_stripped.startswith('//') and not line_stripped.startswith('/*'):
                    results.append({
                        'source': 'c_specific',
                        'config': 'c',
                        'finding': {
                            'check_id': 'c.unchecked-free',
                            'path': 'c_check',
                            'start': {'line': i},
                            'end': {'line': i},
                            'extra': {
                                'message': 'Free without NULL check - Can cause double-free',
                                'severity': 'medium',
                                'lines': line_stripped
                            }
                        }
                    })
        
        return results
    
    @staticmethod
    def _remove_duplicates(results):
        """Remove duplicate findings"""
        unique = []
        seen = set()
        
        for result in results:
            finding = result['finding']
            key = f"{finding.get('check_id', '')}:{finding.get('start', {}).get('line', 0)}:{finding.get('extra', {}).get('message', '')[:50]}"
            
            if key not in seen:
                seen.add(key)
                unique.append(result)
        
        return unique
    
    @staticmethod
    def _process_results(results):
        """Process results into standard format"""
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
        
        for result in results:
            finding = result['finding']
            
            severity = finding.get('extra', {}).get('severity', 'info').lower()
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
            rule_id = finding.get('check_id', 'pattern_match')
            line = finding.get('start', {}).get('line', 0)
            code_snippet = finding.get('extra', {}).get('lines', '')
            
            # Determine type
            finding_type = 'other'
            if any(keyword in message.lower() for keyword in ['sql', 'injection']):
                finding_type = 'sql_injection'
            elif any(keyword in message.lower() for keyword in ['command', 'exec', 'shell']):
                finding_type = 'command_injection'
            elif any(keyword in message.lower() for keyword in ['buffer', 'overflow']):
                finding_type = 'buffer_overflow'
            elif any(keyword in message.lower() for keyword in ['secret', 'password', 'key', 'token']):
                finding_type = 'hardcoded_secret'
            elif any(keyword in message.lower() for keyword in ['deserialization', 'pickle', 'yaml']):
                finding_type = 'insecure_deserialization'
            
            processed["details"].append({
                "severity": severity,
                "message": message,
                "rule_id": rule_id,
                "line": line,
                "code_snippet": code_snippet,
                "type": finding_type,
                "source": result['source']
            })
        
        return processed
    
    @staticmethod
    def scan_file(file_path):
        """Scan uploaded file"""
        try:
            print(f"DEBUG: Scanning file: {file_path}")
            
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}", "by_severity": {}, "details": [], "total_findings": 0}
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return UniversalScanner.scan_code(content, os.path.basename(file_path))
            
        except Exception as e:
            print(f"DEBUG: File scan error: {str(e)}")
            return {"error": str(e), "by_severity": {}, "details": [], "total_findings": 0}

# Test function
def test_universal_scanner():
    print("Testing Universal Scanner...")
    
    # Test with your example code
    test_code = """import sqlite3
import pickle
import base64

# VAST Security Test Case: Web & Logic Vulnerabilities
# 1. Hardcoded Secret (Security Risk)
SECRET_KEY = "VAST_DEBUG_KEY_12345"

def get_user_data(user_id):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    
    # VULNERABILITY: SQL Injection
    # User input is concatenated directly into the query.
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()

def load_session(session_data):
    # VULNERABILITY: Insecure Deserialization
    # 'pickle.loads' on untrusted data can lead to Remote Code Execution (RCE).
    data = base64.b64decode(session_data)
    return pickle.loads(data)

if __name__ == "__main__":
    # Simulate untrusted user input
    malicious_input = "1' OR '1'='1"
    get_user_data(malicious_input)
"""
    
    print("\n" + "="*60)
    print("Scanning test code with Universal Scanner...")
    results = UniversalScanner.scan_code(test_code, 'test.py')
    
    print(f"\nResults:")
    print(f"Total findings: {results.get('total_findings', 0)}")
    print(f"By severity: {results.get('by_severity', {})}")
    
    if results.get('details'):
        print("\nDetailed findings:")
        for i, finding in enumerate(results['details'], 1):
            print(f"\n{i}. [{finding['severity'].upper()}] {finding['rule_id']}")
            print(f"   Source: {finding['source']}")
            print(f"   Line {finding['line']}: {finding['message']}")
            if finding.get('code_snippet'):
                print(f"   Code: {finding['code_snippet']}")
    else:
        print("\nNo findings detected!")

if __name__ == "__main__":
    test_universal_scanner()
