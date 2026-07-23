from flask import Blueprint, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models import Project, ScanResult
from datetime import datetime

bp = Blueprint('dashboard', __name__)

@bp.route('/')
@bp.route('/dashboard')
@login_required
def index():
    # Get user's projects
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.created_at.desc()).all()
    projects_count = len(projects)
    
    # Get scan stats
    total_scans = ScanResult.query.join(Project).filter(
        Project.user_id == current_user.id
    ).count()
    
    critical_findings = ScanResult.query.join(Project).filter(
        Project.user_id == current_user.id,
        ScanResult.severity == 'critical'
    ).count()
    
    # Recent scans
    recent_scans = ScanResult.query.join(Project).filter(
        Project.user_id == current_user.id
    ).order_by(ScanResult.created_at.desc()).limit(5).all()
    
    stats = {
        'total_projects': projects_count,
        'total_scans': total_scans,
        'critical_findings': critical_findings
    }
    
    return render_template('dashboard/index.html', 
                         stats=stats, 
                         recent_scans=recent_scans,
                         projects=projects,
                         now=datetime.now())

@bp.route('/history')
@login_required
def history():
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.created_at.desc()).all()
    return render_template('dashboard/history.html', projects=projects, now=datetime.now())

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
    return redirect(url_for('dashboard.history'))
