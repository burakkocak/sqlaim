import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import secrets
import re

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate a secure random key
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://postgres:password@localhost/kocak')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout after 30 minutes

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256:50000')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login', next=request.url))
        # Check if session is expired (for added security)
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if (datetime.now() - last_activity) > timedelta(minutes=30):
                session.clear()
                flash('Your session has expired. Please log in again', 'info')
                return redirect(url_for('login'))
        # Update last activity timestamp
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login', next=request.url))
        
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Basic input validation
        if not username or not password:
            flash('Please provide both username and password', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        # Check if account is active
        if user and not user.active:
            flash('This account has been deactivated. Please contact an administrator.', 'danger')
            return render_template('login.html')
        
        # Check if account is locked
        if user and user.locked_until and user.locked_until > datetime.now():
            remaining_time = (user.locked_until - datetime.now()).total_seconds() / 60
            flash(f'Account is locked. Try again in {int(remaining_time)} minutes', 'danger')
            return render_template('login.html')
        
        # Check credentials
        if user and user.check_password(password):
            # Reset failed login attempts on successful login
            user.failed_login_attempts = 0
            user.last_login = datetime.now()
            db.session.commit()
            
            # Set session data
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['user_role'] = user.role
            session['last_activity'] = datetime.now().isoformat()
            session.permanent = True  # Use permanent session with the defined lifetime
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Increment failed login attempts
            if user:
                user.failed_login_attempts += 1
                # Lock account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.now() + timedelta(minutes=15)
                    flash('Too many failed login attempts. Account locked for 15 minutes', 'danger')
                else:
                    flash('Invalid username or password', 'danger')
                db.session.commit()
            else:
                # Same error message for non-existent users (prevents username enumeration)
                flash('Invalid username or password', 'danger')
            
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# User Management Routes
@app.route('/users')
@login_required
@admin_required
def user_management():
    users = User.query.all()
    return render_template('user_management.html', users=users)

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        
        # Validate inputs
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('create_user.html')
        
        # Check username format (alphanumeric, underscores, 3-20 chars)
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            flash('Username must be 3-20 characters long and contain only letters, numbers, and underscores', 'danger')
            return render_template('create_user.html')
        
        # Check email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash('Please enter a valid email address', 'danger')
            return render_template('create_user.html')
        
        # Check password strength (min 8 chars, 1 uppercase, 1 lowercase, 1 digit)
        if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password):
            flash('Password must be at least 8 characters long and contain uppercase, lowercase, and numeric characters', 'danger')
            return render_template('create_user.html')
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('create_user.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return render_template('create_user.html')
        
        # Create new user
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash(f'User {username} created successfully', 'success')
            return redirect(url_for('user_management'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'danger')
            return render_template('create_user.html')
    
    return render_template('create_user.html')

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent editing the currently logged-in admin (for safety)
    if user_id == session.get('user_id'):
        flash('You cannot edit your own account here', 'warning')
        return redirect(url_for('user_management'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        role = request.form.get('role')
        active = 'active' in request.form
        new_password = request.form.get('password')
        
        # Validate email
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash('Please enter a valid email address', 'danger')
            return render_template('edit_user.html', user=user)
        
        # Check if email already exists (for a different user)
        existing_user = User.query.filter_by(email=email).first()
        if existing_user and existing_user.id != user_id:
            flash('Email already exists for another user', 'danger')
            return render_template('edit_user.html', user=user)
        
        # Update user details
        user.email = email
        user.role = role
        user.active = active
        
        # Update password if provided
        if new_password:
            if len(new_password) < 8 or not re.search(r'[A-Z]', new_password) or not re.search(r'[a-z]', new_password) or not re.search(r'[0-9]', new_password):
                flash('Password must be at least 8 characters long and contain uppercase, lowercase, and numeric characters', 'danger')
                return render_template('edit_user.html', user=user)
            user.set_password(new_password)
        
        try:
            db.session.commit()
            flash(f'User {user.username} updated successfully', 'success')
            return redirect(url_for('user_management'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'danger')
            return render_template('edit_user.html', user=user)
    
    return render_template('edit_user.html', user=user)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting the currently logged-in admin
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('user_management'))
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('user_management'))

@app.route('/users/unlock/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def unlock_user(user_id):
    user = User.query.get_or_404(user_id)
    
    user.failed_login_attempts = 0
    user.locked_until = None
    
    try:
        db.session.commit()
        flash(f'User {user.username} unlocked successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error unlocking user: {str(e)}', 'danger')
    
    return redirect(url_for('user_management'))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Create initial admin user if none exists
def create_admin_if_not_exists():
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@example.com',
            role='admin'
        )
        admin.set_password('Admin123!')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created: username='admin', password='Admin123!'")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
        create_admin_if_not_exists()  # Create an admin user if none exists
    app.run(debug=False)  # Set to False in production