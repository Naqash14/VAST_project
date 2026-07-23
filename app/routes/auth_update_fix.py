@bp.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    # Get username from form
    username = request.form.get('username')
    
    # If username is not provided, use current username
    if not username:
        username = current_user.username
    
    # Check if username is taken by another user
    if username != current_user.username:
        existing = User.query.filter(User.id != current_user.id, User.username == username).first()
        if existing:
            flash('Username already taken', 'error')
            return redirect(url_for('dashboard.index'))
        current_user.username = username
    
    # Handle profile picture upload
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file and file.filename != '':
            # Validate file type
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
            ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
            if ext not in allowed_extensions:
                flash('Invalid file type. Use PNG, JPG, JPEG, GIF, or WEBP', 'error')
                return redirect(url_for('dashboard.index'))
            
            # Check file size (max 2MB)
            file.seek(0, 2)
            size = file.tell()
            file.seek(0)
            if size > 2 * 1024 * 1024:
                flash('File too large. Max 2MB', 'error')
                return redirect(url_for('dashboard.index'))
            
            # Save file
            filename = secure_filename(f"{current_user.id}_{int(datetime.utcnow().timestamp())}_{file.filename}")
            upload_folder = os.path.join('app', 'static', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            file.save(os.path.join(upload_folder, filename))
            current_user.profile_pic = filename
    
    db.session.commit()
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('dashboard.index'))
