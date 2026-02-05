import subprocess
import json
import tempfile
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class FastScanner:
    """Optimized scanner that runs faster"""
    
    @staticmethod
    def scan_code(code_content, filename=None, max_time=30):
        """Scan code quickly with optimized configuration"""
        try:
            # Determine file extension
            if filename:
                suffix = os.path.splitext(filename)[1] or '.py'
            else:
                # Quick language detection
                if '<?php' in code_content:
                    suffix = '.php'
                elif '#include' in code_content and ('int main' in code_content or 'void main' in code_content):
                    suffix = '.c'
                elif 'public class' in code_content:
                    suffix = '.java'
                elif 'function ' in code_content or 'console.log' in code_content:
                    suffix = '.js'
                elif 'import ' in code_content and ('def ' in code_content or 'class ' in code_content):
                    suffix = '.py'
                else:
                    suffix = '.txt'
            
            # Create temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
                f.write(code_content)
                temp_file = f.name
            
            print(f"DEBUG: Created temp file: {temp_file}")
            
            # Run single optimized command instead of multiple
            results = FastScanner._run_optimized_scan(temp_file, suffix, max_time)
            
            # Clean up
            os.unlink(temp_file)
            
            return FastScanner._process_results(results)
            
        except Exception as e:
            print(f"DEBUG: Error in scan_code: {str(e)}")
            import traceback
            traceback.print_exc()
            return {"error": str(e), "by_severity": {}, "details": [], "total_findings": 0}
    
    @staticmethod
    def _run_optimized_scan(temp_file, suffix, max_time):
        """Run single optimized scan based on file type"""
        all_results = []
        
        # Choose optimal config based on file type
        config_map = {
            '.py': 'auto',  # Auto works best for Python
            '.c': 'p/c',    # C-specific rules
            '.cpp': 'p/c',
            '.h': 'p/c',
            '.hpp': 'p/c',
            '.java': 'p/java',
            '.js': 'auto',
            '.jsx': 'auto',
            '.ts': 'auto',
            '.tsx': 'auto',
            '.php': 'p/php',
            '.rb': 'p/ruby',
            '.go': 'p/go',
            '.rs': 'p/rust',
            '.cs': 'p/csharp'
        }
        
        config = config_map.get(suffix, 'auto')
        print(f"DEBUG: Using optimized config: {config} for {suffix}")
        
        # Run single command with timeout
        cmd = [
            'semgrep', 'scan',
            '--config', config,
            '--json',
            '--metrics', 'off',
            '--no-git-ignore',
            '--timeout', str(max_time),
            '--max-memory', '4096',  # 4GB max
            '--timeout-threshold', '3',  # Skip rules that timeout
            temp_file
        ]
        
        print(f"DEBUG: Running optimized command: {' '.join(cmd[:8])}...")
        results = FastScanner._run_command(cmd, max_time + 5)
        
        if results and 'results' in results:
            all_results.extend(results['results'])
            print(f"DEBUG: Found {len(results['results'])} issues with {config}")
        
        # For critical languages (C/C++), also run basic security rules
        if suffix in ['.c', '.cpp', '.h', '.hpp'] and len(all_results) < 3:
            print(f"DEBUG: Running additional security rules for {suffix}")
            cmd2 = [
                'semgrep', 'scan',
                '--lang', 'c',
                '--json',
                '--metrics', 'off',
                '--no-git-ignore',
                temp_file
            ]
            results2 = FastScanner._run_command(cmd2, 10)
            if results2 and 'results' in results2:
                # Add only new findings
                existing_ids = {r.get('check_id', '') for r in all_results}
                for r in results2['results']:
                    if r.get('check_id', '') not in existing_ids:
                        all_results.append(r)
        
        return {'results': all_results}
    
    @staticmethod
    def _run_command(cmd, timeout):
        """Run command with timeout"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode in [0, 2]:  # 0 = success, 2 = findings
                if result.stdout.strip():
                    return json.loads(result.stdout)
                else:
                    return {"results": []}
            else:
                print(f"DEBUG: Command failed with code {result.returncode}")
                print(f"DEBUG: Stderr: {result.stderr[:200]}")
                return None
                
        except subprocess.TimeoutExpired:
            print(f"DEBUG: Command timeout: {' '.join(cmd[:4])}")
            return None
        except Exception as e:
            print(f"DEBUG: Command error: {str(e)}")
            return None
    
    @staticmethod
    def _process_results(results_data):
        """Process results quickly"""
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
                
                # Quick severity normalization
                if severity == 'warning':
                    severity = 'medium'
                elif severity == 'error':
                    severity = 'high'
                
                if severity not in processed["by_severity"]:
                    severity = 'info'
                
                processed["by_severity"][severity] += 1
                processed["total_findings"] += 1
                
                # Quick processing
                processed["details"].append({
                    "severity": severity,
                    "message": finding.get('extra', {}).get('message', 'No message'),
                    "rule_id": finding.get('check_id', 'Unknown'),
                    "line": finding.get('start', {}).get('line', 0),
                    "code_snippet": finding.get('extra', {}).get('lines', ''),
                    "type": FastScanner._categorize_finding(finding.get('check_id', ''))
                })
        
        print(f"DEBUG: Processed {processed['total_findings']} findings")
        return processed
    
    @staticmethod
    def _categorize_finding(rule_id):
        """Quick categorization"""
        rule_lower = rule_id.lower()
        
        if any(x in rule_lower for x in ['sql', 'injection', 'execute']):
            return 'sql_injection'
        elif any(x in rule_lower for x in ['command', 'exec', 'shell', 'system']):
            return 'command_injection'
        elif any(x in rule_lower for x in ['buffer', 'overflow', 'strcpy', 'gets']):
            return 'buffer_overflow'
        elif any(x in rule_lower for x in ['xss', 'cross-site', 'html']):
            return 'xss'
        elif any(x in rule_lower for x in ['password', 'secret', 'key']):
            return 'hardcoded_secret'
        else:
            return 'other'
    
    @staticmethod
    def scan_file(file_path, max_time=30):
        """Scan uploaded file quickly"""
        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}", "by_severity": {}, "details": [], "total_findings": 0}
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return FastScanner.scan_code(content, os.path.basename(file_path), max_time)
            
        except Exception as e:
            print(f"DEBUG: File scan error: {str(e)}")
            return {"error": str(e), "by_severity": {}, "details": [], "total_findings": 0}

# Test
def test_fast_scanner():
    print("Testing FastScanner...")
    
    # Test vulnerable code
    test_code = """#include <stdio.h>
#include <string.h>

void test(char *input) {
    char buffer[10];
    strcpy(buffer, input);
}

int main() {
    char input[100];
    gets(input);
    test(input);
    return 0;
}
"""
    
    start = time.time()
    results = FastScanner.scan_code(test_code, 'test.c', max_time=15)
    elapsed = time.time() - start
    
    print(f"\nScan completed in {elapsed:.1f} seconds")
    print(f"Total findings: {results.get('total_findings', 0)}")
    print(f"By severity: {results.get('by_severity', {})}")

if __name__ == "__main__":
    import time
    test_fast_scanner()
