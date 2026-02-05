import subprocess
import json
import tempfile
import os
import re

class ForceScanner:
    """Scanner that forces semgrep to find vulnerabilities"""
    
    @staticmethod
    def scan_code(code_content, filename=None):
        """Scan code with aggressive configuration"""
        try:
            # Create temp file with appropriate extension
            if filename:
                suffix = os.path.splitext(filename)[1] or '.py'
            else:
                # Try to detect language from content
                if '<?php' in code_content:
                    suffix = '.php'
                elif '#include' in code_content and 'int main' in code_content:
                    suffix = '.c'
                elif 'public class' in code_content:
                    suffix = '.java'
                elif 'function ' in code_content or 'console.log' in code_content:
                    suffix = '.js'
                elif 'import ' in code_content and 'def ' in code_content:
                    suffix = '.py'
                else:
                    suffix = '.txt'
            
            with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
                f.write(code_content)
                temp_file = f.name
            
            print(f"DEBUG: Created temp file: {temp_file}")
            
            # Run multiple semgrep commands and combine results
            all_results = []
            
            # Command 1: Auto config (most comprehensive)
            print("DEBUG: Running semgrep with auto config...")
            cmd1 = ['semgrep', 'scan', '--config', 'auto', '--json', temp_file]
            results1 = ForceScanner._run_semgrep(cmd1)
            if results1 and 'results' in results1:
                all_results.extend(results1['results'])
                print(f"DEBUG: Auto config found {len(results1['results'])} issues")
            
            # Command 2: Try without config for basic rules
            print("DEBUG: Running semgrep without config...")
            cmd2 = ['semgrep', 'scan', '--json', temp_file]
            results2 = ForceScanner._run_semgrep(cmd2)
            if results2 and 'results' in results2:
                all_results.extend(results2['results'])
                print(f"DEBUG: No config found {len(results2['results'])} issues")
            
            # Command 3: For C/C++ files, use C config
            if suffix in ['.c', '.cpp', '.h', '.hpp']:
                print("DEBUG: Running C-specific rules...")
                cmd3 = ['semgrep', 'scan', '--config', 'p/c', '--json', temp_file]
                results3 = ForceScanner._run_semgrep(cmd3)
                if results3 and 'results' in results3:
                    all_results.extend(results3['results'])
                    print(f"DEBUG: C config found {len(results3['results'])} issues")
            
            # Command 4: For Python files, use python security
            if suffix == '.py':
                print("DEBUG: Running Python security rules...")
                cmd4 = ['semgrep', 'scan', '--config', 'p/security-audit', '--json', temp_file]
                results4 = ForceScanner._run_semgrep(cmd4)
                if results4 and 'results' in results4:
                    all_results.extend(results4['results'])
                    print(f"DEBUG: Python security found {len(results4['results'])} issues")
            
            # Clean up
            os.unlink(temp_file)
            
            # Remove duplicates
            unique_results = []
            seen = set()
            for result in all_results:
                key = f"{result.get('check_id', '')}:{result.get('start', {}).get('line', 0)}"
                if key not in seen:
                    seen.add(key)
                    unique_results.append(result)
            
            print(f"DEBUG: Total unique findings: {len(unique_results)}")
            
            # Process results
            return ForceScanner._process_results({'results': unique_results})
            
        except Exception as e:
            print(f"DEBUG: Error in scan_code: {str(e)}")
            import traceback
            traceback.print_exc()
            return {"error": str(e), "by_severity": {}, "details": [], "total_findings": 0}
    
    @staticmethod
    def _run_semgrep(cmd, timeout=30):
        """Run semgrep command with timeout"""
        try:
            # Add common arguments
            full_cmd = cmd + ['--metrics', 'off', '--no-git-ignore']
            
            print(f"DEBUG: Running: {' '.join(full_cmd[:6])}...")
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode == 0:
                if result.stdout.strip():
                    return json.loads(result.stdout)
                else:
                    return {"results": []}
            elif result.returncode == 2:  # Found issues
                if result.stdout.strip():
                    return json.loads(result.stdout)
                else:
                    return {"results": []}
            else:
                print(f"DEBUG: Semgrep error (code {result.returncode}): {result.stderr[:200]}")
                return None
                
        except subprocess.TimeoutExpired:
            print(f"DEBUG: Timeout for command: {' '.join(cmd[:4])}")
            return None
        except Exception as e:
            print(f"DEBUG: Command error: {str(e)}")
            return None
    
    @staticmethod
    def _process_results(results_data):
        """Process semgrep results"""
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
                rule_id = finding.get('check_id', 'Unknown')
                line = finding.get('start', {}).get('line', 0)
                
                # Get code snippet
                code_snippet = ""
                if 'extra' in finding and 'lines' in finding['extra']:
                    code_snippet = finding['extra']['lines']
                
                # Categorize
                finding_type = 'other'
                rule_lower = rule_id.lower()
                
                if any(x in rule_lower for x in ['sql', 'injection', 'execute']):
                    finding_type = 'sql_injection'
                elif any(x in rule_lower for x in ['command', 'exec', 'shell', 'system']):
                    finding_type = 'command_injection'
                elif any(x in rule_lower for x in ['xss', 'cross-site', 'html']):
                    finding_type = 'xss'
                elif any(x in rule_lower for x in ['buffer', 'overflow', 'strcpy']):
                    finding_type = 'buffer_overflow'
                elif any(x in rule_lower for x in ['password', 'secret', 'key', 'credential']):
                    finding_type = 'hardcoded_secret'
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
            
            return ForceScanner.scan_code(content, os.path.basename(file_path))
            
        except Exception as e:
            print(f"DEBUG: File scan error: {str(e)}")
            return {"error": str(e), "by_severity": {}, "details": [], "total_findings": 0}

# Test
def test_force_scanner():
    print("Testing ForceScanner...")
    
    # Test vulnerable code
    test_code = """#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    char input[100];
    
    printf("Enter input: ");
    gets(input);  // BUFFER OVERFLOW
    
    strcpy(buffer, input);  // BUFFER OVERFLOW
    
    return 0;
}
"""
    
    results = ForceScanner.scan_code(test_code, 'test.c')
    
    print(f"\nResults for C code:")
    print(f"Total findings: {results.get('total_findings', 0)}")
    print(f"By severity: {results.get('by_severity', {})}")
    
    if results.get('details'):
        for i, finding in enumerate(results['details'], 1):
            print(f"\n{i}. [{finding['severity'].upper()}] {finding['rule_id']}")
            print(f"   Line {finding['line']}: {finding['message']}")

if __name__ == "__main__":
    test_force_scanner()
