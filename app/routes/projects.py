from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app import db
from app.models import Project, ScanResult
from app.utils.scanner import UniversalScanner
from app.utils.pdf_generator import PDFReportGenerator
import os
import json
import uuid
from datetime import datetime
import time
import traceback

bp = Blueprint('projects', __name__)

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'py', 'java', 'js', 'jsx', 'ts', 'tsx', 'cpp', 'c', 'h', 'hpp',
    'php', 'rb', 'go', 'rs', 'txt', 'html', 'htm', 'xml', 'json',
    'yml', 'yaml', 'sh', 'bash', 'sql', 'cs', 'swift', 'kt', 'scala',
    'm', 'mm', 'r', 'pl', 'pm', 't', 'sc', 'scala', 'groovy', 'kt',
    'kts', 'vb', 'vbs', 'ps1', 'bat', 'cmd'
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
        print("\n" + "="*80)
        print("CREATE PROJECT - FORM DATA RECEIVED")
        print("="*80)
        
        project_name = request.form.get('project_name', '').strip()
        code_content = request.form.get('code_content', '').strip()
        scanner_type = request.form.get('scanner_type', 'semgrep')
        
        print(f"Project Name: {project_name}")
        print(f"Scanner Type: {scanner_type}")
        print(f"Code Content Length: {len(code_content)}")
        
        # Basic validation
        if not project_name:
            flash('Project name is required', 'error')
            return redirect(url_for('projects.create'))
        
        # Check for file upload
        has_file = False
        uploaded_file_path = None
        file_content = ""
        
        if 'code_file' in request.files:
            file = request.files['code_file']
            if file and file.filename != '':
                print(f"File uploaded: {file.filename}")
                has_file = True
                
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    # Save file
                    upload_folder = os.path.join('app', 'uploads', str(current_user.id))
                    os.makedirs(upload_folder, exist_ok=True)
                    
                    filepath = os.path.join(upload_folder, filename)
                    file.save(filepath)
                    uploaded_file_path = filepath
                    
                    # Read file content
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            file_content = f.read()
                        print(f"Read {len(file_content)} chars from file")
                    except Exception as e:
                        print(f"Error reading file: {e}")
                        flash(f'Error reading file: {str(e)}', 'error')
                        return redirect(url_for('projects.create'))
                else:
                    flash('File type not allowed', 'error')
                    return redirect(url_for('projects.create'))
        
        # Determine which content to use
        if has_file and file_content:
            # Use file content if uploaded
            final_content = file_content
            filename = os.path.basename(uploaded_file_path) if uploaded_file_path else ''
            print(f"Using file content. Length: {len(final_content)}")
        elif code_content:
            # Use textarea content
            final_content = code_content
            filename = ''
            print(f"Using textarea content. Length: {len(final_content)}")
        else:
            # No content provided
            flash('Please provide code content or upload a file', 'error')
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
            code_content=final_content,
            filename=filename if has_file else ''
        )
        
        db.session.add(project)
        db.session.commit()
        
        flash(f'Project "{project_name}" created successfully!', 'success')
        
        # Perform immediate scan if semgrep is selected
        if scanner_type == 'semgrep':
            return redirect(url_for('projects.perform_scan', project_id=project.id, tool='semgrep'))
        else:
            flash(f'{scanner_type.capitalize()} analysis will be implemented soon!', 'info')
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
    
    print(f"\n" + "="*80)
    print(f"PERFORMING SCAN FOR PROJECT: {project.project_name}")
    print(f"Tool: {tool}")
    print(f"Code length: {len(project.code_content) if project.code_content else 0}")
    print(f"Filename: {project.filename}")
    print("="*80)
    
    if tool == 'semgrep':
        try:
            start_time = time.time()
            
            # Use UniversalScanner
            if project.filename:
                filepath = os.path.join('app', 'uploads', str(current_user.id), project.filename)
                print(f"Scanning file: {filepath}")
                
                if os.path.exists(filepath):
                    results = UniversalScanner.scan_file(filepath)
                else:
                    results = {"error": f"File not found: {filepath}", "by_severity": {}, "details": [], "total_findings": 0}
                    print(f"ERROR: File not found at {filepath}")
            else:
                print("Scanning code content directly")
                results = UniversalScanner.scan_code(project.code_content, project.filename)
            
            scan_time = time.time() - start_time
            
            print(f"\nSCAN RESULTS:")
            print(f"Scan time: {scan_time:.1f} seconds")
            print(f"Total findings: {results.get('total_findings', 0)}")
            print(f"By severity: {results.get('by_severity', {})}")
            
            if 'error' in results:
                print(f"Error in results: {results['error']}")
            
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
                
                # Generate success message
                findings_count = results.get('total_findings', 0)
                if findings_count > 0:
                    # Show breakdown of findings
                    by_sev = results.get('by_severity', {})
                    sev_details = []
                    for sev in ['critical', 'high', 'medium', 'low', 'info']:
                        count = by_sev.get(sev, 0)
                        if count > 0:
                            sev_details.append(f"{count} {sev}")
                    
                    if sev_details:
                        flash(f'Scan completed in {scan_time:.1f} seconds! Found {findings_count} issues ({", ".join(sev_details)}).', 'success')
                    else:
                        flash(f'Scan completed in {scan_time:.1f} seconds! Found {findings_count} issues.', 'success')
                else:
                    flash(f'Scan completed in {scan_time:.1f} seconds! No security issues found.', 'success')
                    
            else:
                error_msg = results.get("error", "Unknown error")
                print(f"SCAN FAILED: {error_msg}")
                flash(f'Scan failed: {error_msg}', 'error')
                
        except Exception as e:
            error_msg = f'Scan error: {str(e)}'
            print(f"EXCEPTION DURING SCAN: {error_msg}")
            traceback.print_exc()
            flash(error_msg, 'error')
    
    elif tool in ['klee', 'libfuzzer', 'hybrid']:
        flash(f'{tool.capitalize()} analysis will be implemented soon!', 'info')
    
    return redirect(url_for('projects.scan', project_id=project.id))

@bp.route('/rescan/<int:project_id>', methods=['POST'])
@login_required
def rescan(project_id):
    """Rescan a project"""
    project = Project.query.get_or_404(project_id)
    
    if project.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Delete old scans for this project
    ScanResult.query.filter_by(project_id=project.id).delete()
    db.session.commit()
    
    flash('Old scan results cleared. Starting new scan...', 'info')
    return redirect(url_for('projects.perform_scan', project_id=project.id, tool='semgrep'))

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
    try:
        scan_result = ScanResult.query.get_or_404(scan_id)
        project = Project.query.get_or_404(scan_result.project_id)
        
        # Check if project belongs to current user
        if project.user_id != current_user.id:
            flash('Unauthorized access', 'error')
            return redirect(url_for('dashboard.index'))
        
        # Parse findings
        findings = json.loads(scan_result.findings) if scan_result.findings else {}
        
        # Create unique filename
        safe_project_name = ''.join(c for c in project.project_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        report_filename = f"VAST_Report_{safe_project_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        # FIXED PATH: Use correct relative path
        report_path = os.path.join('reports', report_filename)
        
        # Ensure reports directory exists (relative to app directory)
        reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        # Full path for PDF generation
        full_report_path = os.path.join(reports_dir, report_filename)
        
        print(f"\nDEBUG: Generating PDF report...")
        print(f"DEBUG: Report filename: {report_filename}")
        print(f"DEBUG: Reports directory: {reports_dir}")
        print(f"DEBUG: Full report path: {full_report_path}")
        print(f"DEBUG: Directory exists: {os.path.exists(reports_dir)}")
        
        # Generate PDF
        pdf_generator = PDFReportGenerator(full_report_path)
        pdf_generator.generate_vulnerability_report(
            project_data={'project_name': project.project_name},
            scan_results=findings.get('by_severity', {}),
            user_info={
                'username': current_user.username,
                'email': current_user.email
            },
            findings_details=findings.get('details', [])
        )
        
        print(f"DEBUG: PDF generation completed")
        print(f"DEBUG: File exists: {os.path.exists(full_report_path)}")
        
        if os.path.exists(full_report_path):
            # Send file from the correct path
            return send_file(
                full_report_path,
                as_attachment=True,
                download_name=report_filename,
                mimetype='application/pdf'
            )
        else:
            flash('Report file not found after generation', 'error')
            return redirect(url_for('projects.scan', project_id=project.id))
            
    except Exception as e:
        error_msg = f'Failed to generate report: {str(e)}'
        print(f"ERROR in download_report: {error_msg}")
        traceback.print_exc()
        flash(error_msg, 'error')
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

@bp.route('/delete-project/<int:project_id>', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if project belongs to current user
    if project.user_id != current_user.id:
        flash('Unauthorized action', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Delete associated scans first
    ScanResult.query.filter_by(project_id=project.id).delete()
    
    # Delete the project
    db.session.delete(project)
    db.session.commit()
    
    flash('Project deleted successfully', 'success')
    return redirect(url_for('projects.existing'))
