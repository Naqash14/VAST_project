import subprocess
import json
import tempfile
import os
import time

class SingleConfigScanner:
    """Scanner that uses only one optimized configuration"""
    
    @staticmethod
    def scan_code(code_content, filename=None, timeout=20):
        """Scan with single optimized config"""
        try:
            # Create temp file with proper extension
            ext = SingleConfigScanner._detect_extension(code_content, filename)
            
            with tempfile.NamedTemporaryFile(mode='w', suffix=ext, delete=False) as f:
                f.write(code_content)
                temp_file = f.name
            
            # Get optimal single config
            config = SingleConfigScanner._get_optimal_config(ext)
            print(f"DEBUG: Using single config: {config} for {ext}")
            
            # Run single command
            results = SingleConfigScanner._run_single_scan(temp_file, config, timeout)
            
            # Clean up
            os.unlink(temp_file)
            
            return SingleConfigScanner._process_fast(results)
            
        except Exception as e:
            print(f"ERROR in scan_code: {str(e)}")
            return {"error": str(e), "by_severity": {}, "details": [], "total_findings": 0}
    
    @staticmethod
    def _detect_extension(code_content, filename):
        """Detect file extension from content or filename"""
        if filename:
            ext = os.path.splitext(filename)[1]
            if ext:
                return ext
        
        # Detect from content
        first_lines = code_content[:500].lower()
        
        if '<?php' in first_lines:
            return '.php'
        elif '#include' in first_lines and ('int main' in first_lines or 'void main' in first_lines):
            return '.c'
        elif 'public class' in first_lines:
            return '.java'
        elif 'function ' in first_lines or 'console.log' in first_lines or 'var ' in first_lines:
            return '.js'
        elif 'import ' in first_lines and ('def ' in first_lines or 'class ' in first_lines):
            return '.py'
        elif '#include' in first_lines:
            return '.cpp'
        else:
            return '.txt'
    
    @staticmethod
    def _get_optimal_config(ext):
        """Get optimal single config for file type"""
        config_map = {
            '.py': 'auto',      # Auto has good Python coverage
            '.c': 'p/c',        # C-specific rules
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
            '.cs': 'p/csharp',
            '.swift': 'p/swift',
            '.kt': 'p/kotlin'
        }
        return config_map.get(ext, 'auto')
    
    @staticmethod
    def _run_single_scan(temp_file, config, timeout):
        """Run single scan command with optimizations"""
        # Optimized command for speed
        cmd = [
            'semgrep', 'scan',
            '--config', config,
            '--json',
            '--metrics', 'off',
            '--no-git-ignore',
            '--no-rewrite-rule-ids',
            '--timeout', str(timeout),
            '--max-memory', '2048',  # 2GB max
            '--timeout-threshold', '2',  # Skip slow rules
            '--max-target-bytes', '100000',  # 100KB max per file
            temp_file
        ]
        
        print(f"DEBUG: Running: {' '.join(cmd[:4])}... (timeout: {timeout}s)")
        start_time = time.time()
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            elapsed = time.time() - start_time
            
            print(f"DEBUG: Scan completed in {elapsed:.1f}s with code {result.returncode}")
            
            if result.returncode in [0, 2]:  # Success or findings
                if result.stdout.strip():
                    data = json.loads(result.stdout)
                    print(f"DEBUG: Found {len(data.get('results', []))} issues")
                    return data
                else:
                    return {"results": []}
            else:
                print(f"DEBUG: Semgrep error: {result.stderr[:200]}")
                return {"results": []}
                
        except subprocess.TimeoutExpired:
            print(f"DEBUG: Scan timeout after {timeout}s")
            return {"results": []}
        except Exception as e:
            print(f"DEBUG: Scan error: {str(e)}")
            return {"results": []}
    
    @staticmethod
    def _process_fast(results_data):
        """Fast processing of results"""
        processed = {
            "total_findings": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "details": []
        }
        
        if 'results' in results_data:
            for finding in results_data['results']:
                severity = finding.get('extra', {}).get('severity', 'info').lower()
                
                # Quick mapping
                if severity == 'warning':
                    severity = 'medium'
                elif severity == 'error':
                    severity = 'high'
                elif severity not in processed["by_severity"]:
                    severity = 'info'
                
                processed["by_severity"][severity] += 1
                processed["total_findings"] += 1
                
                processed["details"].append({
                    "severity": severity,
                    "message": finding.get('extra', {}).get('message', ''),
                    "rule_id": finding.get('check_id', ''),
                    "line": finding.get('start', {}).get('line', 0),
                    "code_snippet": finding.get('extra', {}).get('lines', '')
                })
        
        return processed
    
    @staticmethod
    def scan_file(file_path, timeout=20):
        """Scan file with single config"""
        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}", "by_severity": {}, "details": [], "total_findings": 0}
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return SingleConfigScanner.scan_code(content, os.path.basename(file_path), timeout)
            
        except Exception as e:
            print(f"ERROR in scan_file: {str(e)}")
            return {"error": str(e), "by_severity": {}, "details": [], "total_findings": 0}

# Test
if __name__ == "__main__":
    print("Testing SingleConfigScanner...")
    
    # Test Python
    py_code = """
import sqlite3
import os

def bad_sql(user_id):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()

def bad_cmd(host):
    os.system("ping " + host)
"""
    
    print("\nTesting Python code...")
    start = time.time()
    results = SingleConfigScanner.scan_code(py_code, 'test.py', timeout=15)
    elapsed = time.time() - start
    
    print(f"Time: {elapsed:.1f}s")
    print(f"Findings: {results['total_findings']}")
    print(f"Severities: {results['by_severity']}")
    
    # Test C
    c_code = """
#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buffer[10];
    strcpy(buffer, input);
}

int main() {
    char input[100];
    gets(input);
    vulnerable(input);
    return 0;
}
"""
    
    print("\nTesting C code...")
    start = time.time()
    results = SingleConfigScanner.scan_code(c_code, 'test.c', timeout=15)
    elapsed = time.time() - start
    
    print(f"Time: {elapsed:.1f}s")
    print(f"Findings: {results['total_findings']}")
    print(f"Severities: {results['by_severity']}")
