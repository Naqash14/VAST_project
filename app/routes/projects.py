from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app import db
from app.models import Project, ScanResult
from app.utils.scanner import UniversalScanner
from app.utils.symbolic_analyzer import SymbolicAnalyzer
from app.utils.fuzz_tester import FuzzTester
from app.utils.pdf_generator import PDFReportGenerator
import os
import json
from datetime import datetime
import time
import traceback

bp = Blueprint('projects', __name__)

ALLOWED_EXTENSIONS = {
    'py', 'java', 'js', 'jsx', 'ts', 'tsx', 'cpp', 'c', 'h', 'hpp',
    'php', 'rb', 'go', 'rs', 'txt', 'html', 'htm', 'xml', 'json',
    'yml', 'yaml', 'sh', 'bash', 'sql', 'cs', 'swift', 'kt', 'scala'
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def detect_language(code_content):
    if not code_content:
        return 'python'
    code_lower = code_content[:1000].lower()
    if '#include' in code_lower or 'int main' in code_lower or 'printf' in code_lower:
        return 'c'
    if 'import java.' in code_lower or 'public class' in code_lower:
        return 'java'
    if 'import ' in code_lower or 'def ' in code_lower or 'print(' in code_lower:
        return 'python'
    return 'python'

def run_ai_analysis(scan_result, findings, language, context=None):
    try:
        from app.utils.ai_service import AIPrioritizer
        ai = AIPrioritizer()
        if ai.available:
            print(f"🤖 AI analyzing {len(findings)} findings...")
            result = ai.analyze_findings(findings, language, context)
            scan_result.ai_analysis = json.dumps(result)
            scan_result.ai_status = 'complete'
            db.session.commit()
            return True
        else:
            scan_result.ai_status = 'failed'
            db.session.commit()
            return False
    except Exception as e:
        print(f"❌ AI error: {e}")
        scan_result.ai_status = 'failed'
        db.session.commit()
        return False

def get_tool_info_for_language(language):
    tools = {'c': 'KLEE', 'cpp': 'KLEE', 'python': 'Angr', 'java': 'JPF'}
    return tools.get(language, 'Symbolic')

def get_highest_severity(results):
    if not results or 'by_severity' not in results:
        return 'info'
    by_severity = results.get('by_severity', {})
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        if by_severity.get(sev, 0) > 0:
            return sev
    return 'info'

@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        project_name = request.form.get('project_name', '').strip()
        code_content = request.form.get('code_content', '').strip()
        scanner_type = request.form.get('scanner_type', 'semgrep')
        
        if not project_name:
            flash('Project name required', 'error')
            return redirect(url_for('projects.create'))
        
        has_file = False
        file_content = ""
        
        if 'code_file' in request.files:
            file = request.files['code_file']
            if file and file.filename != '':
                has_file = True
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    upload_folder = os.path.join('app', 'uploads', str(current_user.id))
                    os.makedirs(upload_folder, exist_ok=True)
                    filepath = os.path.join(upload_folder, filename)
                    file.save(filepath)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            file_content = f.read()
                    except Exception as e:
                        flash(f'Error reading file: {str(e)}', 'error')
                        return redirect(url_for('projects.create'))
                else:
                    flash('File type not allowed', 'error')
                    return redirect(url_for('projects.create'))
        
        final_content = file_content if has_file and file_content else code_content
        filename = ''
        
        if not final_content:
            flash('Please provide code or upload a file', 'error')
            return redirect(url_for('projects.create'))
        
        existing = Project.query.filter_by(user_id=current_user.id, project_name=project_name).first()
        if existing:
            flash('Project name exists', 'error')
            return redirect(url_for('projects.create'))
        
        project = Project(
            user_id=current_user.id,
            project_name=project_name,
            code_content=final_content,
            filename=filename
        )
        db.session.add(project)
        db.session.commit()
        
        flash(f'Project "{project_name}" created!', 'success')
        return redirect(url_for('projects.perform_scan', project_id=project.id, tool=scanner_type))
    
    return render_template('projects/create.html', now=datetime.now())

@bp.route('/scan/<int:project_id>')
@login_required
def scan(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard.index'))
    
    scan_results = ScanResult.query.filter_by(project_id=project.id).order_by(ScanResult.created_at.desc()).all()
    parsed_results = []
    for result in scan_results:
        try:
            findings = json.loads(result.findings) if result.findings else {'by_severity': {}, 'details': []}
            parsed_results.append({
                'id': result.id,
                'tool': result.tool_name,
                'severity': result.severity,
                'findings': findings,
                'created_at': result.created_at,
                'ai_status': result.ai_status,
                'ai_analysis': result.ai_analysis
            })
        except:
            parsed_results.append({
                'id': result.id,
                'tool': result.tool_name,
                'severity': result.severity,
                'findings': {'by_severity': {}, 'details': []},
                'created_at': result.created_at,
                'ai_status': result.ai_status,
                'ai_analysis': result.ai_analysis
            })
    
    return render_template('projects/scan.html', project=project, scan_results=parsed_results, now=datetime.now())

@bp.route('/perform-scan/<int:project_id>/<tool>')
@login_required
def perform_scan(project_id, tool):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard.index'))
    
    language = detect_language(project.code_content)
    print(f"\n📊 Performing {tool} scan on {project.project_name} ({language})")
    
    if tool == 'semgrep':
        try:
            scanner = UniversalScanner()
            results = scanner.scan_code(project.code_content, project.filename)
            
            if 'error' not in results:
                scan_result = ScanResult(
                    project_id=project.id,
                    tool_name='semgrep',
                    findings=json.dumps(results),
                    severity=get_highest_severity(results)
                )
                db.session.add(scan_result)
                db.session.commit()
                
                run_ai_analysis(scan_result, results.get('details', []), language, f"Project: {project.project_name}")
                
                flash(f'Static: Found {results.get("total_findings", 0)} issues', 'success')
            else:
                flash(f'Static failed: {results["error"]}', 'error')
        except Exception as e:
            flash(f'Static error: {str(e)}', 'error')
    
    elif tool == 'symbolic':
        try:
            symbolic = SymbolicAnalyzer()
            results = symbolic.analyze(project.code_content, language, project.filename)
            
            actual_tool = get_tool_info_for_language(language)
            formatted = {
                "total_findings": len(results.get('findings', [])),
                "by_severity": {},
                "details": results.get('findings', [])
            }
            for f in results.get('findings', []):
                sev = f.get('severity', 'info')
                formatted["by_severity"][sev] = formatted["by_severity"].get(sev, 0) + 1
            
            scan_result = ScanResult(
                project_id=project.id,
                tool_name=f'symbolic_{actual_tool}',
                findings=json.dumps(formatted),
                severity=get_highest_severity(formatted)
            )
            db.session.add(scan_result)
            db.session.commit()
            
            run_ai_analysis(scan_result, results.get('findings', []), language, f"Project: {project.project_name}")
            
            flash(f'Symbolic ({actual_tool}): Found {len(results.get("findings", []))} issues', 'success')
        except Exception as e:
            flash(f'Symbolic error: {str(e)}', 'error')
    
    elif tool == 'fuzz':
        try:
            fuzzer = FuzzTester()
            results = fuzzer.fuzz(project.code_content, language, project.filename)
            
            formatted = {
                "total_findings": len(results.get('findings', [])),
                "by_severity": {},
                "details": results.get('findings', [])
            }
            for f in results.get('findings', []):
                sev = f.get('severity', 'info')
                formatted["by_severity"][sev] = formatted["by_severity"].get(sev, 0) + 1
            
            scan_result = ScanResult(
                project_id=project.id,
                tool_name='fuzz',
                findings=json.dumps(formatted),
                severity=get_highest_severity(formatted)
            )
            db.session.add(scan_result)
            db.session.commit()
            
            run_ai_analysis(scan_result, results.get('findings', []), language, f"Project: {project.project_name}")
            
            flash(f'Fuzz: Found {len(results.get("findings", []))} issues', 'success')
        except Exception as e:
            flash(f'Fuzz error: {str(e)}', 'error')
    
    elif tool == 'hybrid':
        flash('🔄 Hybrid Analysis: Running all tools...', 'info')
        
        # Run all three tools
        all_findings = []
        tools_run = []
        
        # 1. Static Analysis
        try:
            scanner = UniversalScanner()
            static_results = scanner.scan_code(project.code_content, project.filename)
            if 'error' not in static_results:
                scan_result = ScanResult(
                    project_id=project.id,
                    tool_name='hybrid_static',
                    findings=json.dumps(static_results),
                    severity=get_highest_severity(static_results)
                )
                db.session.add(scan_result)
                db.session.commit()
                tools_run.append('Static')
                all_findings.extend(static_results.get('details', []))
        except Exception as e:
            print(f"Hybrid Static error: {e}")
        
        # 2. Symbolic Analysis
        try:
            symbolic = SymbolicAnalyzer()
            sym_results = symbolic.analyze(project.code_content, language, project.filename)
            actual_tool = get_tool_info_for_language(language)
            formatted = {
                "total_findings": len(sym_results.get('findings', [])),
                "by_severity": {},
                "details": sym_results.get('findings', [])
            }
            for f in sym_results.get('findings', []):
                sev = f.get('severity', 'info')
                formatted["by_severity"][sev] = formatted["by_severity"].get(sev, 0) + 1
            scan_result = ScanResult(
                project_id=project.id,
                tool_name=f'hybrid_symbolic_{actual_tool}',
                findings=json.dumps(formatted),
                severity=get_highest_severity(formatted)
            )
            db.session.add(scan_result)
            db.session.commit()
            tools_run.append('Symbolic')
            all_findings.extend(formatted.get('details', []))
        except Exception as e:
            print(f"Hybrid Symbolic error: {e}")
        
        # 3. Fuzz Testing
        try:
            fuzzer = FuzzTester()
            fuzz_results = fuzzer.fuzz(project.code_content, language, project.filename)
            formatted = {
                "total_findings": len(fuzz_results.get('findings', [])),
                "by_severity": {},
                "details": fuzz_results.get('findings', [])
            }
            for f in fuzz_results.get('findings', []):
                sev = f.get('severity', 'info')
                formatted["by_severity"][sev] = formatted["by_severity"].get(sev, 0) + 1
            scan_result = ScanResult(
                project_id=project.id,
                tool_name='hybrid_fuzz',
                findings=json.dumps(formatted),
                severity=get_highest_severity(formatted)
            )
            db.session.add(scan_result)
            db.session.commit()
            tools_run.append('Fuzz')
            all_findings.extend(formatted.get('details', []))
        except Exception as e:
            print(f"Hybrid Fuzz error: {e}")
        
        # Combined AI analysis
        if all_findings:
            combined_result = {
                "total_findings": len(all_findings),
                "by_severity": {},
                "details": all_findings
            }
            for f in all_findings:
                sev = f.get('severity', 'info')
                combined_result["by_severity"][sev] = combined_result["by_severity"].get(sev, 0) + 1
            
            scan_result = ScanResult(
                project_id=project.id,
                tool_name='hybrid_combined',
                findings=json.dumps(combined_result),
                severity=get_highest_severity(combined_result)
            )
            db.session.add(scan_result)
            db.session.commit()
            
            run_ai_analysis(scan_result, all_findings, language, f"Project: {project.project_name} - Hybrid")
        
        flash(f'✅ Hybrid Complete! Ran: {", ".join(tools_run)}. Found {len(all_findings)} total issues.', 'success')
    
    return redirect(url_for('projects.scan', project_id=project.id))

# ===== EXISTING PROJECTS ROUTE =====
@bp.route('/existing')
@login_required
def existing():
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.created_at.desc()).all()
    return render_template('projects/existing.html', projects=projects, now=datetime.now())

@bp.route('/view/<int:project_id>')
@login_required
def view(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard.index'))
    scan_results = ScanResult.query.filter_by(project_id=project.id).order_by(ScanResult.created_at.desc()).all()
    return render_template('projects/view.html', project=project, scan_results=scan_results, now=datetime.now())

@bp.route('/download-report/<int:scan_id>')
@login_required
def download_report(scan_id):
    try:
        scan_result = ScanResult.query.get_or_404(scan_id)
        project = Project.query.get_or_404(scan_result.project_id)
        if project.user_id != current_user.id:
            flash('Unauthorized access', 'error')
            return redirect(url_for('dashboard.index'))
        
        findings = json.loads(scan_result.findings) if scan_result.findings else {}
        safe_name = ''.join(c for c in project.project_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        report_filename = f"VAST_Report_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        full_path = os.path.join(reports_dir, report_filename)
        
        ai_data = None
        if scan_result.ai_analysis:
            try:
                ai_data = json.loads(scan_result.ai_analysis)
            except:
                pass
        
        pdf_generator = PDFReportGenerator(full_path)
        pdf_generator.generate_vulnerability_report(
            project_data={'project_name': project.project_name},
            scan_results=findings.get('by_severity', {}),
            user_info={'username': current_user.username, 'email': current_user.email},
            findings_details=findings.get('details', []),
            ai_data=ai_data
        )
        
        return send_file(full_path, as_attachment=True, download_name=report_filename, mimetype='application/pdf')
    except Exception as e:
        flash(f'Failed to generate report: {str(e)}', 'error')
        return redirect(url_for('projects.scan', project_id=project.id))

@bp.route('/delete-scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    project = Project.query.get_or_404(scan_result.project_id)
    if project.user_id != current_user.id:
        flash('Unauthorized action', 'error')
        return redirect(url_for('dashboard.index'))
    db.session.delete(scan_result)
    db.session.commit()
    flash('Scan result deleted', 'success')
    return redirect(url_for('projects.scan', project_id=project.id))

@bp.route('/delete-project/<int:project_id>', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        flash('Unauthorized action', 'error')
        return redirect(url_for('dashboard.index'))
    ScanResult.query.filter_by(project_id=project.id).delete()
    db.session.delete(project)
    db.session.commit()
    flash('Project deleted', 'success')
    return redirect(url_for('projects.existing'))
