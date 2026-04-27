"""
Hybrid Analysis Module
Runs Static -> Symbolic -> Fuzz in sequence
Combines results from all three techniques
"""

from app.utils.scanner import UniversalScanner
from app.utils.symbolic_analyzer import SymbolicAnalyzer
from app.utils.fuzz_tester import FuzzTester
import time


class HybridAnalyzer:
    
    def __init__(self):
        self.static_scanner = UniversalScanner()
        self.symbolic_analyzer = SymbolicAnalyzer()
        self.fuzz_tester = FuzzTester()
    
    def analyze(self, code_content, language, filename=None):
        """
        Run all three analyses sequentially and combine results
        """
        print(f"\n{'='*60}")
        print(f"🔬 HYBRID ANALYSIS for {language.upper()}")
        print(f"{'='*60}")
        
        results = {
            "language": language,
            "timestamp": time.time(),
            "static_analysis": {},
            "symbolic_analysis": {},
            "fuzz_testing": {},
            "combined_findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        
        # ========== STEP 1: STATIC ANALYSIS ==========
        print("\n📊 STEP 1: Running Static Analysis (Semgrep)...")
        try:
            static_result = self.static_scanner.scan_code(code_content, filename)
            results["static_analysis"] = static_result
            self._add_findings(results, static_result.get('details', []), "Static")
            print(f"   ✅ Static found {len(static_result.get('details', []))} issues")
        except Exception as e:
            print(f"   ❌ Static error: {e}")
            results["static_analysis"] = {"error": str(e)}
        
        # ========== STEP 2: SYMBOLIC ANALYSIS ==========
        print("\n🧠 STEP 2: Running Symbolic Analysis...")
        try:
            symbolic_result = self.symbolic_analyzer.analyze(code_content, language, filename)
            results["symbolic_analysis"] = symbolic_result
            self._add_findings(results, symbolic_result.get('findings', []), "Symbolic")
            print(f"   ✅ Symbolic found {len(symbolic_result.get('findings', []))} issues")
        except Exception as e:
            print(f"   ❌ Symbolic error: {e}")
            results["symbolic_analysis"] = {"error": str(e)}
        
        # ========== STEP 3: FUZZ TESTING ==========
        print("\n🎲 STEP 3: Running Fuzz Testing...")
        try:
            fuzz_result = self.fuzz_tester.fuzz(code_content, language, filename)
            results["fuzz_testing"] = fuzz_result
            self._add_findings(results, fuzz_result.get('findings', []), "Fuzz")
            print(f"   ✅ Fuzz found {len(fuzz_result.get('findings', []))} issues")
        except Exception as e:
            print(f"   ❌ Fuzz error: {e}")
            results["fuzz_testing"] = {"error": str(e)}
        
        # ========== SUMMARY ==========
        print(f"\n{'='*60}")
        print(f"📊 HYBRID ANALYSIS COMPLETE")
        print(f"   Total Findings: {results['summary']['total_findings']}")
        print(f"   Critical: {results['summary']['critical']}")
        print(f"   High: {results['summary']['high']}")
        print(f"   Medium: {results['summary']['medium']}")
        print(f"   Low: {results['summary']['low']}")
        print(f"{'='*60}")
        
        return results
    
    def _add_findings(self, results, findings, source):
        """Add findings to combined results and update summary"""
        for finding in findings:
            finding['source'] = source
            results["combined_findings"].append(finding)
            
            severity = finding.get('severity', 'info').lower()
            if severity in results["summary"]:
                results["summary"][severity] += 1
            results["summary"]["total_findings"] += 1

