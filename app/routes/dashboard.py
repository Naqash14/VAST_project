from flask import Blueprint, render_template, jsonify, request, flash, redirect, url_for, send_file
from flask_login import login_required, current_user
from app import db
from app.models import Project, ScanResult
import json
import os
from datetime import datetime

bp = Blueprint('dashboard', __name__)

@bp.route('/')
@bp.route('/dashboard')
@login_required
def index():
    # Get user's projects count
    projects_count = Project.query.filter_by(user_id=current_user.id).count()
    
    # Get recent scans
    recent_scans = ScanResult.query.join(Project).filter(
        Project.user_id == current_user.id
    ).order_by(ScanResult.created_at.desc()).limit(5).all()
    
    # Calculate statistics
    stats = {
        'total_projects': projects_count,
        'scans_today': ScanResult.query.join(Project).filter(
            Project.user_id == current_user.id,
            db.func.date(ScanResult.created_at) == db.func.date('now')
        ).count(),
        'critical_findings': ScanResult.query.join(Project).filter(
            Project.user_id == current_user.id,
            ScanResult.severity == 'critical'
        ).count()
    }
    
    return render_template('dashboard/index.html', 
                         stats=stats,
                         recent_scans=recent_scans,
                         now=datetime.now())

@bp.route('/history')
@login_required
def history():
    # Get all user projects with their scan results
    projects = Project.query.filter_by(
        user_id=current_user.id
    ).order_by(Project.created_at.desc()).all()
    
    return render_template('dashboard/history.html', 
                         projects=projects,
                         now=datetime.now())

@bp.route('/delete-project/<int:project_id>', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if project belongs to current user
    if project.user_id != current_user.id:
        flash('Unauthorized action', 'error')
        return redirect(url_for('dashboard.history'))
    
    # Delete project and associated scans
    db.session.delete(project)
    db.session.commit()
    
    flash('Project deleted successfully', 'success')
    return redirect(url_for('dashboard.history'))
