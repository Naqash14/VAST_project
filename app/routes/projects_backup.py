from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app import db
from app.models import Project, ScanResult
# Import the scanner - try simple one first
try:
    from app.utils.scanner_simple import CodeScanner
    print("DEBUG: Using simple scanner for testing")
except ImportError:
    from app.utils.scanner import CodeScanner
    print("DEBUG: Using main scanner")
from app.utils.pdf_generator import PDFReportGenerator
import os
import json
import uuid
from datetime import datetime
import time
import traceback

bp = Blueprint('projects', __name__)

# Allowed file extensions (based on semgrep support)
ALLOWED_EXTENSIONS = {
    'py', 'java', 'js', 'ts', 'jsx', 'tsx', 'cpp', 'c', 'cs', 
    'php', 'rb', 'go', 'rs', 'kt', 'swift', 'scala'
}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_highest_severity(results):
    """Get highest severity level from scan results"""
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
        project_name = request.form.get('project_name')
        code_content = request.form.get('code_content')
        scanner_type = request.form.get('scanner_type', 'semgrep')
        language = request.form.get('language', '')
        
        print(f"DEBUG: Creating project: {project_name}, scanner: {scanner_type}")
        
        if not project_name:
            flash('Project name is required', 'error')
            return redirect(url_for('projects.create'))
        
        # Check if project name already exists for this user
        existing = Project.query.filter_by(
            user_id=current_user.id,
            project_name=project_name
        ).first()
        
        if existing:
            flash('Project with this name already exists', 'error')
            return redirect(url_for('projects.create'))
        
        # Create new project
        project = Project(
            user_id=current_user.id,
            project_name=project_name,
            code_content=code_content if code_content else '',
            filename=''
        )
        
        # Check if file was uploaded
        if 'code_file' in request.files:
            file = request.files['code_file']
            if file and file.filename != '':
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    # Save file
                    upload_folder = os.path.join('app', 'uploads', str(current_user.id))
                    os.makedirs(upload_folder, exist_ok=True)
                    
                    filepath = os.path.join(upload_folder, filename)
                    file.save(filepath)
                    
                    project.filename = filename
                    
                    # Read file content if no code content provided
                    if not code_content:
                        with open(filepath, 'r') as f:
                            project.code_content = f.read()
                else:
                    flash('File type not allowed. Supported: Python, Java, JS, C/C++, C#, PHP, Ruby, Go, Rust, Kotlin, etc.', 'error')
                    return redirect(url_for('projects.create'))
        
        db.session.add(project)
        db.session.commit()
        
        flash(f'Project "{project_name}" created successfully!', 'success')
        
        # Perform scan if semgrep selected
        if scanner_type == 'semgrep':
            print(f"DEBUG: Redirecting to perform scan for project {project.id}")
            return redirect(url_for('projects.perform_scan', project_id=project.id, tool='semgrep'))
        elif scanner_type in ['klee', 'libfuzzer', 'hybrid']:
            flash(f'{scanner_type.capitalize()} analysis will be implemented soon! Redirecting to project...', 'info')
            return redirect(url_for('projects.scan', project_id=project.id))
        else:
            return redirect(url_for('projects.scan', project_id=project.id))
    
    return render_template('projects/create.html', now=datetime.now())

@bp.route('/scan/<int:project_id>')
@login_required
def scan(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if project belongs to current user
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Get existing scan results
    scan_results = ScanResult.query.filter_by(project_id=project.id).order_by(ScanResult.created_at.desc()).all()
    
    # Parse findings for display
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
    
    return render_template('projects/scan.html', 
                         project=project, 
                         scan_results=parsed_results,
                         now=datetime.now())

@bp.route('/perform-scan/<int:project_id>/<tool>')
@login_required
def perform_scan(project_id, tool):
    project = Project.query.get_or_404(project_id)
    
    # Check if project belongs to current user
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard.index'))
    
    print(f"DEBUG: Performing scan with tool: {tool}")
    
    if tool == 'semgrep':
        try:
            # Initialize scanner
            scanner = CodeScanner('app/uploads')
            
            print(f"DEBUG: Scanner initialized, scanning project {project.id}")
            print(f"DEBUG: Project has filename: {project.filename}")
            print(f"DEBUG: Code content length: {len(project.code_content) if project.code_content else 0}")
            
            start_time = time.time()
            
            if project.filename:
                filepath = os.path.join('app', 'uploads', str(current_user.id), project.filename)
                print(f"DEBUG: Scanning file: {filepath}")
                if os.path.exists(filepath):
                    results = scanner.scan_file(filepath)
                else:
                    results = {"error": f"File not found: {filepath}", "by_severity": {}, "details": []}
            else:
                print(f"DEBUG: Scanning code content directly")
                results = scanner.scan_with_semgrep(project.code_content)
            
            scan_time = time.time() - start_time
            
            print(f"DEBUG: Scan completed in {scan_time:.1f} seconds")
            print(f"DEBUG: Results keys: {results.keys() if isinstance(results, dict) else 'Not a dict'}")
            
            # Save results to database
            if 'error' not in results:
                scan_result = ScanResult(
                    project_id=project.id,
                    tool_name='semgrep',
                    findings=json.dumps(results),
                    severity=get_highest_severity(results)
                )
                db.session.add(scan_result)
                db.session.commit()
                
                flash(f'Semgrep scan completed in {scan_time:.1f} seconds! Found {results.get("total_findings", 0)} issues.', 'success')
            else:
                error_msg = results.get("error", "Unknown error")
                print(f"DEBUG: Scan failed: {error_msg}")
                flash(f'Semgrep scan failed: {error_msg}', 'error')
                
        except Exception as e:
            error_msg = f'Scan error: {str(e)}'
            print(f"DEBUG: Exception during scan: {error_msg}")
            print(traceback.format_exc())
            flash(error_msg, 'error')
    
    elif tool in ['klee', 'libfuzzer', 'hybrid']:
        flash(f'{tool.capitalize()} analysis will be implemented soon!', 'info')
    
    return redirect(url_for('projects.scan', project_id=project.id))

@bp.route('/existing')
@login_required
def existing():
    # Get all user projects
    projects = Project.query.filter_by(
        user_id=current_user.id
    ).order_by(Project.created_at.desc()).all()
    
    return render_template('projects/existing.html', 
                         projects=projects,
                         now=datetime.now())

@bp.route('/view/<int:project_id>')
@login_required
def view(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if project belongs to current user
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Get scan results for this project
    scan_results = ScanResult.query.filter_by(project_id=project.id).order_by(ScanResult.created_at.desc()).all()
    
    return render_template('projects/view.html', 
                         project=project, 
                         scan_results=scan_results,
                         now=datetime.now())

@bp.route('/download-report/<int:scan_id>')
@login_required
def download_report(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    project = Project.query.get_or_404(scan_result.project_id)
    
    # Check if project belongs to current user
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Generate PDF report
    try:
        findings = json.loads(scan_result.findings) if scan_result.findings else {}
        
        # Create unique filename
        report_filename = f"vast_report_{project.project_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        report_path = os.path.join('app', 'reports', report_filename)
        
        # Ensure reports directory exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        # Generate PDF
        pdf_generator = PDFReportGenerator(report_path)
        pdf_generator.generate_vulnerability_report(
            project_data={'project_name': project.project_name},
            scan_results=findings.get('by_severity', {}),
            user_info={
                'username': current_user.username,
                'email': current_user.email
            }
        )
        
        return send_file(report_path, as_attachment=True)
        
    except Exception as e:
        flash(f'Failed to generate report: {str(e)}', 'error')
        return redirect(url_for('projects.scan', project_id=project.id))

@bp.route('/delete-scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    project = Project.query.get_or_404(scan_result.project_id)
    
    # Check if project belongs to current user
    if project.user_id != current_user.id:
        flash('Unauthorized action', 'error')
        return redirect(url_for('dashboard.index'))
    
    db.session.delete(scan_result)
    db.session.commit()
    
    flash('Scan result deleted successfully', 'success')
    return redirect(url_for('projects.scan', project_id=project.id))
