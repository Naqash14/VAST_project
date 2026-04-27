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


def is_language_supported(language):
    """Check if language is supported for analysis"""
    supported = ['c', 'python', 'java']
    return language in supported

def validate_language(code_content):
    """Validate if code language is supported"""
    lang = detect_language(code_content)
    if not is_language_supported(lang):
        return False, lang, f"Unsupported language detected: {lang}. Only C/C++, Python, and Java are supported."
    return True, lang, None


def detect_language(code_content):
    code_lower = code_content[:500].lower()
    
    # Check for Java FIRST
    if 'import java.' in code_lower or 'public class' in code_lower:
        return 'java'
    
    # Check for C/C++
    if '#include' in code_lower:
        return 'c'
    if 'int main' in code_lower and ('printf' in code_lower or 'strcpy' in code_lower):
        return 'c'
    if 'void ' in code_lower and 'char *' in code_lower:
        return 'c'
    
    # Check for Python
    if 'def ' in code_lower and ':' in code_lower:
        return 'python'
    if 'import ' in code_lower and ('os' in code_lower or 'sys' in code_lower):
        return 'python'
    
    return 'python'

def get_highest_severity(results):
    if not results or 'by_severity' not in results:
        return 'info'
    by_severity = results.get('by_severity', {})
    severities = ['critical', 'high', 'medium', 'low', 'info']
    for severity in severities:
        if by_severity.get(severity, 0) > 0:
            return severity
    return 'info'

@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        project_name = request.form.get('project_name', '').strip()
        code_content = request.form.get('code_content', '').strip()
        scanner_type = request.form.get('scanner_type', 'semgrep')
        
        if not project_name:
            flash('Project name is required', 'error')
            return redirect(url_for('projects.create'))
        
        has_file = False
        uploaded_file_path = None
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
                    uploaded_file_path = filepath
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            file_content = f.read()
                    except Exception as e:
                        flash(f'Error reading file: {str(e)}', 'error')
                        return redirect(url_for('projects.create'))
                else:
                    flash('File type not allowed', 'error')
                    return redirect(url_for('projects.create'))
        
        if has_file and file_content:
            final_content = file_content
            filename = os.path.basename(uploaded_file_path) if uploaded_file_path else ''
        elif code_content:
            final_content = code_content
            filename = ''
        else:
            flash('Please provide code content or upload a file', 'error')
            return redirect(url_for('projects.create'))
        
        existing = Project.query.filter_by(user_id=current_user.id, project_name=project_name).first()
        if existing:
            flash('Project with this name already exists', 'error')
            return redirect(url_for('projects.create'))
        
        project = Project(
            user_id=current_user.id,
            project_name=project_name,
            code_content=final_content,
            filename=filename if has_file else ''
        )
        db.session.add(project)
        db.session.commit()
        
        flash(f'Project "{project_name}" created successfully!', 'success')
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
                'created_at': result.created_at
            })
        except:
            parsed_results.append({
                'id': result.id,
                'tool': result.tool_name,
                'severity': result.severity,
                'findings': {'by_severity': {}, 'details': []},
                'created_at': result.created_at
            })
    
    return render_template('projects/scan.html', project=project, scan_results=parsed_results, now=datetime.now())

@bp.route('/perform-scan/<int:project_id>/<tool>')
@login_required
def perform_scan(project_id, tool):
    project = Project.query.get_or_404(project_id)
    
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard.index'))
    
    print(f"\n{'='*80}")
    print(f"PERFORMING SCAN: {project.project_name}")
    print(f"Tool: {tool}")
    print(f"{'='*80}")
    
    language = detect_language(project.code_content)
    
    # Check if language is supported
    supported, detected_lang, error_msg = validate_language(project.code_content)
    if not supported:
        flash(error_msg, "error")
        return redirect(url_for("projects.scan", project_id=project.id))
    
    print(f"Detected language: {language}")
    
    # ========== STATIC ANALYSIS ==========
    if tool == 'semgrep':
        try:
            start_time = time.time()
            scanner = UniversalScanner()
            results = scanner.scan_code(project.code_content, project.filename)
            scan_time = time.time() - start_time
            
            if 'error' not in results:
                scan_result = ScanResult(
                    project_id=project.id,
                    tool_name='semgrep',
                    findings=json.dumps(results),
                    severity=get_highest_severity(results)
                )
                db.session.add(scan_result)
                db.session.commit()
                
                findings_count = results.get('total_findings', 0)
                if findings_count > 0:
                    flash(f'Static Analysis: Found {findings_count} issues', 'success')
                else:
                    flash(f'Static Analysis: No issues found', 'success')
            else:
                flash(f'Static Analysis failed: {results["error"]}', 'error')
                
        except Exception as e:
            flash(f'Static Analysis error: {str(e)}', 'error')
            traceback.print_exc()
    
    # ========== SYMBOLIC ANALYSIS ==========
    elif tool == 'symbolic':
        try:
            start_time = time.time()
            symbolic_analyzer = SymbolicAnalyzer()
            results = symbolic_analyzer.analyze(project.code_content, language, project.filename)
            scan_time = time.time() - start_time
            
            formatted_results = {
                "total_findings": len(results.get('findings', [])),
                "by_severity": {},
                "details": results.get('findings', [])
            }
            
            for finding in results.get('findings', []):
                severity = finding.get('severity', 'info')
                formatted_results["by_severity"][severity] = formatted_results["by_severity"].get(severity, 0) + 1
            
            scan_result = ScanResult(
                project_id=project.id,
                tool_name='symbolic',
                findings=json.dumps(formatted_results),
                severity=get_highest_severity(formatted_results)
            )
            db.session.add(scan_result)
            db.session.commit()
            
            findings_count = len(results.get('findings', []))
            if findings_count > 0:
                flash(f'Symbolic Analysis: Found {findings_count} issues', 'success')
            else:
                flash(f'Symbolic Analysis: No issues found', 'success')
                
        except Exception as e:
            flash(f'Symbolic Analysis error: {str(e)}', 'error')
            traceback.print_exc()
    
    # ========== FUZZ TESTING ==========
    elif tool == 'fuzz':
        try:
            start_time = time.time()
            fuzzer = FuzzTester()
            results = fuzzer.fuzz(project.code_content, language, project.filename)
            scan_time = time.time() - start_time
            
            formatted_results = {
                "total_findings": len(results.get('findings', [])),
                "by_severity": {},
                "details": results.get('findings', [])
            }
            
            for finding in results.get('findings', []):
                severity = finding.get('severity', 'info')
                formatted_results["by_severity"][severity] = formatted_results["by_severity"].get(severity, 0) + 1
            
            scan_result = ScanResult(
                project_id=project.id,
                tool_name='fuzz',
                findings=json.dumps(formatted_results),
                severity=get_highest_severity(formatted_results)
            )
            db.session.add(scan_result)
            db.session.commit()
            
            findings_count = len(results.get('findings', []))
            if findings_count > 0:
                flash(f'Fuzz Testing: Found {findings_count} edge-case issues', 'success')
            else:
                flash(f'Fuzz Testing: No edge-case vulnerabilities found', 'success')
                
        except Exception as e:
            flash(f'Fuzz Testing error: {str(e)}', 'error')
            traceback.print_exc()
    
    # ========== HYBRID ANALYSIS ==========
    elif tool == 'hybrid':
        try:
            from app.utils.hybrid_analyzer import HybridAnalyzer
            start_time = time.time()
            hybrid_analyzer = HybridAnalyzer()
            results = hybrid_analyzer.analyze(project.code_content, language, project.filename)
            scan_time = time.time() - start_time
            
            formatted_results = {
                "total_findings": results['summary']['total_findings'],
                "by_severity": {
                    "critical": results['summary']['critical'],
                    "high": results['summary']['high'],
                    "medium": results['summary']['medium'],
                    "low": results['summary']['low'],
                    "info": results['summary']['info']
                },
                "details": results['combined_findings'],
                "static_analysis": results.get('static_analysis', {}),
                "symbolic_analysis": results.get('symbolic_analysis', {}),
                "fuzz_testing": results.get('fuzz_testing', {})
            }
            
            scan_result = ScanResult(
                project_id=project.id,
                tool_name='hybrid',
                findings=json.dumps(formatted_results),
                severity=get_highest_severity(formatted_results)
            )
            db.session.add(scan_result)
            db.session.commit()
            
            findings_count = results['summary']['total_findings']
            if findings_count > 0:
                flash(f'Hybrid Analysis Complete! Found {findings_count} issues across Static, Symbolic, and Fuzz testing.', 'success')
            else:
                flash(f'Hybrid Analysis Complete! No vulnerabilities found.', 'success')
                
        except Exception as e:
            flash(f'Hybrid Analysis error: {str(e)}', 'error')
            traceback.print_exc()
    
    else:
        flash(f'{tool.capitalize()} analysis not recognized', 'error')
    
    return redirect(url_for('projects.scan', project_id=project.id))

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
        
        pdf_generator = PDFReportGenerator(full_path)
        pdf_generator.generate_vulnerability_report(
            project_data={'project_name': project.project_name},
            scan_results=findings.get('by_severity', {}),
            user_info={'username': current_user.username, 'email': current_user.email},
            findings_details=findings.get('details', [])
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
