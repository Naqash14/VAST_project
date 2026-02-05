import subprocess
import json
import tempfile
import os
from datetime import datetime

class CodeScanner:
    def __init__(self, upload_folder):
        self.upload_folder = upload_folder
    
    def scan_with_semgrep(self, code_content, filename=None):
        """Scan code using semgrep with proper configuration"""
        try:
            # Create temporary file for scanning
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(code_content)
                temp_file = f.name
            
            print(f"DEBUG: Scanning file: {temp_file}")
            print(f"DEBUG: Code content length: {len(code_content)}")
            print(f"DEBUG: First 200 chars: {code_content[:200]}")
            
            # Try multiple configurations in order
            all_findings = []
            configs_tried = []
            
            # Try these configurations in order
            configs_to_try = [
                ('auto', 'Auto configuration'),  # This includes security rules
                ('p/security-audit', 'Security audit rules'),
                ('p/python', 'Python rules'),
                ('p/javascript', 'JavaScript rules'),
                ('p/java', 'Java rules'),
                ('p/c', 'C rules'),
                ('p/cpp', 'C++ rules'),
                ('p/php', 'PHP rules'),
                ('p/go', 'Go rules'),
                ('p/ruby', 'Ruby rules')
            ]
            
            for config, config_name in configs_to_try:
                try:
                    print(f"DEBUG: Trying config: {config_name} ({config})")
                    results = self._run_semgrep_with_timeout(temp_file, config)
                    if results and 'results' in results and results['results']:
                        print(f"DEBUG: Found {len(results['results'])} issues with {config}")
                        all_findings.extend(results['results'])
                        configs_tried.append(f"{config_name}: {len(results['results'])} findings")
                        # Don't break - collect from all configs
                    else:
                        configs_tried.append(f"{config_name}: 0 findings")
                except Exception as e:
                    print(f"DEBUG: Error with config {config}: {str(e)}")
                    configs_tried.append(f"{config_name}: ERROR")
            
            # If no findings with specific configs, try community rules
            if not all_findings:
                print("DEBUG: Trying community rules...")
                results = self._run_semgrep_community(temp_file)
                if results and 'results' in results and results['results']:
                    all_findings.extend(results['results'])
                    configs_tried.append(f"Community rules: {len(results['results'])} findings")
            
            # Clean up temp file
            os.unlink(temp_file)
            
            print(f"DEBUG: Total unique findings across all configs: {len(all_findings)}")
            print(f"DEBUG: Configs tried: {configs_tried}")
            
            return self._process_semgrep_findings({'results': all_findings})
                
        except Exception as e:
            print(f"DEBUG: Exception in scan_with_semgrep: {str(e)}")
            import traceback
            traceback.print_exc()
            return {"error": str(e), "by_severity": {}, "details": [], "total_findings": 0, "configs_tried": []}
    
    def _run_semgrep_with_timeout(self, file_path, config, timeout=30):
        """Run semgrep with timeout"""
        try:
            # Use --metrics off to speed up
            cmd = ['semgrep', '--config', config, '--json', '--metrics', 'off', file_path]
            print(f"DEBUG: Running: {' '.join(cmd[:4])}...")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            elif result.stderr:
                print(f"DEBUG: Stderr for config {config}: {result.stderr[:200]}")
                
        except subprocess.TimeoutExpired:
            print(f"DEBUG: Timeout with config {config}")
        except Exception as e:
            print(f"DEBUG: Error with config {config}: {str(e)}")
        
        return None
    
    def _run_semgrep_community(self, file_path):
        """Run semgrep with community rules only"""
        try:
            # Get file extension to determine language
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()
            
            # Map extensions to semgrep language identifiers
            lang_map = {
                '.py': 'python',
                '.js': 'javascript',
                '.jsx': 'javascript',
                '.ts': 'typescript',
                '.tsx': 'typescript',
                '.java': 'java',
                '.c': 'c',
                '.cpp': 'c',
                '.cc': 'c',
                '.cxx': 'c',
                '.h': 'c',
                '.hpp': 'c',
                '.php': 'php',
                '.rb': 'ruby',
                '.go': 'go',
                '.rs': 'rust',
                '.cs': 'csharp',
                '.swift': 'swift',
                '.kt': 'kotlin'
            }
            
            language = lang_map.get(ext, 'python')
            print(f"DEBUG: Detected language: {language} for extension {ext}")
            
            # Run with language-specific rules
            cmd = ['semgrep', '--lang', language, '--json', '--metrics', 'off', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
                
        except Exception as e:
            print(f"DEBUG: Error with community rules: {str(e)}")
        
        return None
    
    def _process_semgrep_findings(self, findings_data):
        """Process and categorize semgrep findings"""
        processed = {
            "total_findings": 0,
            "by_severity": {
                "critical": 0, 
                "high": 0, 
                "medium": 0, 
                "low": 0, 
                "info": 0
            },
            "details": [],
            "configs_tried": []
        }
        
        if 'results' in findings_data:
            seen_issues = set()  # To avoid duplicates
            
            for finding in findings_data['results']:
                # Create unique ID for this finding to avoid duplicates
                issue_id = f"{finding.get('check_id', '')}:{finding.get('start', {}).get('line', 0)}"
                
                if issue_id in seen_issues:
                    continue
                seen_issues.add(issue_id)
                
                severity = finding.get('extra', {}).get('severity', 'info').lower()
                
                # Normalize severity names
                if severity == 'warning':
                    severity = 'medium'
                elif severity == 'error':
                    severity = 'high'
                
                if severity not in processed["by_severity"]:
                    severity = 'info'
                
                processed["by_severity"][severity] += 1
                processed["total_findings"] += 1
                
                # Extract relevant information
                message = finding.get('extra', {}).get('message', 'No message')
                rule_id = finding.get('check_id', 'Unknown')
                line = finding.get('start', {}).get('line', 0)
                col = finding.get('start', {}).get('col', 0)
                
                # Get code snippet
                code_snippet = ""
                if 'extra' in finding and 'lines' in finding['extra']:
                    code_snippet = finding['extra']['lines']
                
                # Categorize the finding type
                finding_type = 'other'
                rule_lower = rule_id.lower()
                
                type_keywords = {
                    'sql_injection': ['sql', 'injection', 'execute', 'query', 'database'],
                    'command_injection': ['command', 'exec', 'shell', 'system', 'popen', 'subprocess'],
                    'xss': ['xss', 'cross-site', 'html', 'dom', 'innerhtml', 'document.write'],
                    'path_traversal': ['path', 'traversal', 'directory', 'file', 'open'],
                    'auth': ['auth', 'password', 'credential', 'token', 'secret', 'key'],
                    'crypto': ['crypto', 'encrypt', 'hash', 'md5', 'sha1', 'random'],
                    'buffer_overflow': ['buffer', 'overflow', 'strcpy', 'gets', 'sprintf'],
                    'xxe': ['xxe', 'xml', 'external', 'entity'],
                    'deserialization': ['pickle', 'yaml', 'marshal', 'deserialization']
                }
                
                for ftype, keywords in type_keywords.items():
                    if any(keyword in rule_lower for keyword in keywords):
                        finding_type = ftype
                        break
                
                processed["details"].append({
                    "severity": severity,
                    "message": message,
                    "rule_id": rule_id,
                    "line": line,
                    "column": col,
                    "file": finding.get('path', ''),
                    "type": finding_type,
                    "code_snippet": code_snippet,
                    "metadata": finding.get('extra', {}).get('metadata', {})
                })
        
        print(f"DEBUG: Processed {processed['total_findings']} unique findings")
        return processed
    
    def scan_file(self, file_path):
        """Scan uploaded file"""
        try:
            print(f"DEBUG: Scanning uploaded file: {file_path}")
            
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}", "by_severity": {}, "details": [], "total_findings": 0}
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            print(f"DEBUG: File content length: {len(content)}")
            print(f"DEBUG: File extension: {os.path.splitext(file_path)[1]}")
            
            return self.scan_with_semgrep(content, os.path.basename(file_path))
            
        except Exception as e:
            print(f"DEBUG: Exception in scan_file: {str(e)}")
            return {"error": str(e), "by_severity": {}, "details": [], "total_findings": 0}

# Alternative: Direct command scanner
class DirectScanner:
    """Scanner that runs semgrep directly with optimal arguments"""
    
    @staticmethod
    def scan_code_directly(code_content, language='auto'):
        """Scan code directly with optimized semgrep command"""
        try:
            # Create temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False) as f:
                f.write(code_content)
                temp_file = f.name
            
            # Determine best config based on language
            if language == 'auto':
                # Try to detect language from content
                if 'import sqlite3' in code_content or 'def ' in code_content and ':' in code_content:
                    language = 'python'
                elif '<?php' in code_content:
                    language = 'php'
                elif '#include' in code_content and 'int main' in code_content:
                    language = 'c'
                elif 'public class' in code_content:
                    language = 'java'
                elif 'function ' in code_content and '{' in code_content:
                    language = 'javascript'
                else:
                    language = 'python'
            
            print(f"DEBUG: Using language: {language}")
            
            # Run semgrep with optimized arguments
            # --no-rewrite-rule-ids: faster
            # --no-git-ignore: scan all
            # --metrics off: no telemetry
            cmd = [
                'semgrep', 'scan',
                '--config', 'auto',
                '--lang', language,
                '--json',
                '--no-rewrite-rule-ids',
                '--no-git-ignore',
                '--metrics', 'off',
                '--timeout', '30',
                temp_file
            ]
            
            print(f"DEBUG: Running optimized command")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Clean up
            os.unlink(temp_file)
            
            if result.returncode == 0:
                if result.stdout:
                    return json.loads(result.stdout)
                else:
                    return {"results": []}
            else:
                print(f"DEBUG: Semgrep error: {result.stderr}")
                return {"error": result.stderr, "results": []}
                
        except Exception as e:
            print(f"DEBUG: Direct scan error: {str(e)}")
            return {"error": str(e), "results": []}

# Test function
def test_scanner():
    print("Testing improved scanner...")
    
    scanner = CodeScanner('test_uploads')
    
    # Test with known vulnerable code
    test_code = """
import sqlite3
import os

# SQL Injection
def test1(user_id):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # SQL INJECTION
    return cursor.fetchone()

# Command Injection
def test2(host):
    os.system("ping " + host)  # COMMAND INJECTION

# Hardcoded password
PASSWORD = "admin123"  # HARDCODED SECRET

# Pickle deserialization
import pickle
def test3(data):
    return pickle.loads(data)  # INSECURE DESERIALIZATION
"""
    
    print("\nScanning test code with improved scanner...")
    results = scanner.scan_with_semgrep(test_code)
    
    print(f"\nResults:")
    print(f"Total findings: {results.get('total_findings', 0)}")
    print(f"By severity: {results.get('by_severity', {})}")
    
    if results.get('details'):
        print("\nDetailed findings:")
        for i, finding in enumerate(results['details'], 1):
            print(f"\n{i}. [{finding['severity'].upper()}] {finding['rule_id']}")
            print(f"   Line {finding['line']}: {finding['message']}")
            if finding.get('code_snippet'):
                print(f"   Code: {finding['code_snippet']}")
    
    # Test direct scanner
    print("\n" + "="*60)
    print("Testing direct scanner...")
    direct_results = DirectScanner.scan_code_directly(test_code, 'python')
    
    if 'results' in direct_results and direct_results['results']:
        print(f"Direct scanner found {len(direct_results['results'])} issues:")
        for i, finding in enumerate(direct_results['results'][:3], 1):
            print(f"\n{i}. {finding.get('check_id', 'Unknown')}")
            print(f"   {finding.get('extra', {}).get('message', 'No message')}")
    else:
        print("Direct scanner found 0 issues")

if __name__ == "__main__":
    test_scanner()
