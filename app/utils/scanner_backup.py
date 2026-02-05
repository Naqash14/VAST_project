import subprocess
import json
import tempfile
import os
from datetime import datetime
import traceback
import shutil

class CodeScanner:
    def __init__(self, upload_folder):
        self.upload_folder = upload_folder
    
    def scan_with_semgrep(self, code_content, filename=None):
        """Scan code using semgrep with improved error handling"""
        try:
            # Check if code content is empty
            if not code_content or not code_content.strip():
                return {"error": "No code content provided", "by_severity": {}, "details": []}
            
            # Check if semgrep is installed
            semgrep_path = shutil.which('semgrep')
            if not semgrep_path:
                return {"error": "Semgrep is not installed or not in PATH", 
                        "by_severity": {}, "details": []}
            
            # Create temporary file for scanning
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(code_content)
                temp_file = f.name
            
            try:
                # Run semgrep command with simplified config to avoid timeout
                # Use --config r/python.lang.security for faster scanning
                cmd = ['semgrep', '--config', 'r/python.lang.security', '--json', temp_file]
                
                print(f"Running semgrep command: {' '.join(cmd)}")
                
                # Run semgrep with longer timeout
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=120,
                    env={**os.environ, 'SEMGREP_USER_AGENT_APPEND': 'vast-scanner'}
                )
                
                print(f"Semgrep return code: {result.returncode}")
                print(f"Semgrep stdout length: {len(result.stdout)}")
                print(f"Semgrep stderr length: {len(result.stderr)}")
                
                if result.stderr:
                    print(f"Semgrep stderr: {result.stderr[:500]}")
                
                if result.returncode in [0, 1]:  # semgrep returns 1 when findings are found
                    try:
                        if result.stdout.strip():
                            findings = json.loads(result.stdout)
                            print(f"Successfully parsed JSON, findings: {len(findings.get('results', []))}")
                            return self._process_semgrep_findings(findings)
                        else:
                            return {"error": "Empty response from semgrep", 
                                    "by_severity": {}, "details": []}
                    except json.JSONDecodeError as e:
                        print(f"JSON decode error: {e}")
                        print(f"First 500 chars of output: {result.stdout[:500]}")
                        # Try to parse anyway for partial results
                        try:
                            # Find JSON in output
                            start = result.stdout.find('{')
                            end = result.stdout.rfind('}') + 1
                            if start != -1 and end != -1:
                                json_str = result.stdout[start:end]
                                findings = json.loads(json_str)
                                return self._process_semgrep_findings(findings)
                        except:
                            pass
                        return {"error": f"Invalid JSON response from semgrep: {str(e)}", 
                                "by_severity": {}, "details": []}
                else:
                    error_msg = result.stderr if result.stderr else f"Exit code: {result.returncode}"
                    print(f"Semgrep error: {error_msg}")
                    
                    # Try to parse stdout even with error
                    if result.stdout:
                        try:
                            findings = json.loads(result.stdout)
                            return self._process_semgrep_findings(findings)
                        except:
                            pass
                    
                    return {"error": f"Semgrep error: {error_msg}", 
                            "by_severity": {}, "details": []}
                    
            except subprocess.TimeoutExpired:
                print("Semgrep scan timed out (120 seconds)")
                # Try with even simpler config
                try:
                    print("Trying with basic config...")
                    cmd = ['semgrep', '--config', 'p/default', '--json', temp_file]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if result.returncode in [0, 1] and result.stdout:
                        try:
                            findings = json.loads(result.stdout)
                            return self._process_semgrep_findings(findings)
                        except:
                            pass
                except:
                    pass
                
                return {"error": "Semgrep scan timed out. Try with smaller code.", 
                        "by_severity": {}, "details": []}
            except Exception as e:
                print(f"Semgrep execution error: {str(e)}")
                print(traceback.format_exc())
                return {"error": f"Semgrep execution error: {str(e)}", 
                        "by_severity": {}, "details": []}
            finally:
                # Clean up temp file
                try:
                    os.unlink(temp_file)
                except:
                    pass
                
        except Exception as e:
            print(f"Unexpected error in scan_with_semgrep: {str(e)}")
            print(traceback.format_exc())
            return {"error": f"Unexpected error: {str(e)}", 
                    "by_severity": {}, "details": []}
    
    def _process_semgrep_findings(self, findings_data):
        """Process and categorize semgrep findings"""
        processed = {
            "total_findings": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "details": []
        }
        
        try:
            if 'results' in findings_data:
                print(f"Processing {len(findings_data['results'])} findings")
                for finding in findings_data['results']:
                    severity = finding.get('extra', {}).get('severity', 'info').lower()
                    if severity not in processed["by_severity"]:
                        severity = 'info'
                    
                    processed["by_severity"][severity] += 1
                    processed["total_findings"] += 1
                    
                    processed["details"].append({
                        "severity": severity,
                        "message": finding.get('extra', {}).get('message', ''),
                        "rule_id": finding.get('check_id', ''),
                        "line": finding.get('start', {}).get('line', 0),
                        "file": finding.get('path', ''),
                        "metadata": finding.get('extra', {}).get('metadata', {})
                    })
            elif 'error' in findings_data:
                processed["error"] = findings_data['error']
        except Exception as e:
            print(f"Error processing findings: {str(e)}")
            processed["error"] = f"Error processing findings: {str(e)}"
        
        print(f"Processed findings: {processed['total_findings']} total")
        return processed
    
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
            print(f"Error in scan_file: {str(e)}")
            return {"error": str(e), "by_severity": {}, "details": []}
