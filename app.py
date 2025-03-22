import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import secrets

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate a secure random key
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://postgres:password@localhost/kocak')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout afpip ter 30 minutes

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    
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

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=False)  # Set to False in production