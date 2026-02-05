import os
from datetime import datetime

def download_report_fixed(scan_id):
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
        
        # FIXED PATH: Use absolute path from current directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        reports_dir = os.path.join(current_dir, '..', 'reports')
        report_path = os.path.join(reports_dir, report_filename)
        
        # Ensure reports directory exists
        os.makedirs(reports_dir, exist_ok=True)
        
        print(f"Generating PDF report:")
        print(f"  Report path: {report_path}")
        print(f"  Reports dir: {reports_dir}")
        print(f"  Current dir: {current_dir}")
        
        # Generate PDF
        pdf_generator = PDFReportGenerator(report_path)
        pdf_generator.generate_vulnerability_report(
            project_data={'project_name': project.project_name},
            scan_results=findings.get('by_severity', {}),
            user_info={
                'username': current_user.username,
                'email': current_user.email
            },
            findings_details=findings.get('details', [])
        )
        
        print(f"PDF generated successfully: {report_path}")
        
        if os.path.exists(report_path):
            return send_file(
                report_path,
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
        import traceback
        traceback.print_exc()
        flash(error_msg, 'error')
        return redirect(url_for('projects.scan', project_id=project.id))
