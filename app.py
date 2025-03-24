import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import secrets
import re
import uuid
import sqlparse
from sqlalchemy import text
import requests

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
    role = db.Column(db.String(20), default='user')  # 'admin', 'approver', or 'user'
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

# SQL Query model
class SqlQuery(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    query_text = db.Column(db.Text, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approval_date = db.Column(db.DateTime, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    is_executed = db.Column(db.Boolean, default=False)
    execution_date = db.Column(db.DateTime, nullable=True)
    execution_result = db.Column(db.Text, nullable=True)
    llm_analysis= db.Column(db.Text,nullable=True)
    approval_recommendation = db.Column(db.String(20), default='pending')  # 'recommended', 'not_recommended', or 'pending'
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='queries')
    approver = db.relationship('User', foreign_keys=[approved_by])
    
    def __repr__(self):
        return f'<SqlQuery {self.id}>'

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bu sayfaya erişmek için lütfen giriş yapın.', 'danger')
            return redirect(url_for('login', next=request.url))
        # Check if session is expired (for added security)
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if (datetime.now() - last_activity) > timedelta(minutes=30):
                session.clear()
                flash('Oturumunuz sona erdi. Lütfen tekrar giriş yapın.', 'info')
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
            flash('Bu sayfaya erişmek için lütfen giriş yapın.', 'danger')
            return redirect(url_for('login', next=request.url))
        
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Bu sayfayı görmeye yetkiniz yok', 'danger')
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

# Approver required decorator
def approver_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bu sayfaya erişmek için giriş yapın.', 'danger')
            return redirect(url_for('login', next=request.url))
        
        user = User.query.get(session['user_id'])
        if not user or (user.role != 'approver' and user.role != 'admin'):
            flash('Bu sayfayı görmeye yetkiniz yok', 'danger')
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
            flash('Lütfen kullanıcı adı ve parola bilgisini girin.', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        # Check if account is active
        if user and not user.active:
            flash('Bu hesap kapanmış, lütfen admin ile iletişime geçin.', 'danger')
            return render_template('login.html')
        
        # Check if account is locked
        if user and user.locked_until and user.locked_until > datetime.now():
            remaining_time = (user.locked_until - datetime.now()).total_seconds() / 60
            flash(f'Hesap blokeli lütfen {int(remaining_time)} dakika sonra tekrar deneyin', 'danger')
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
            
            flash('Giriş Başarılı!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Increment failed login attempts
            if user:
                user.failed_login_attempts += 1
                # Lock account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.now() + timedelta(minutes=5)
                    flash('Çok fazla hatalı giriş nedeniyle hesap 5 dakika blokelendi.', 'danger')
                else:
                    flash('Hatalı kullanıcı adı veya parola', 'danger')
                db.session.commit()
            else:
                # Same error message for non-existent users (prevents username enumeration)
                flash('Hatalı kullanıcı adı veya parola', 'danger')
            
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    
    # Get counts for different query statuses
    pending_count = SqlQuery.query.filter_by(user_id=user.id, status='pending').count()
    approved_count = SqlQuery.query.filter_by(user_id=user.id, status='approved').count()
    rejected_count = SqlQuery.query.filter_by(user_id=user.id, status='rejected').count()
    executed_count = SqlQuery.query.filter_by(user_id=user.id, is_executed=True).count()
    
    # For approvers, get count of pending approvals
    pending_approvals = 0
    if user.role in ['admin', 'approver']:
        pending_approvals = SqlQuery.query.filter_by(status='pending').count()
    
    return render_template('dashboard.html', 
                           user=user, 
                           pending_count=pending_count,
                           approved_count=approved_count,
                           rejected_count=rejected_count,
                           executed_count=executed_count,
                           pending_approvals=pending_approvals)

@app.route('/user_dashboard') 
@login_required
def user_dashboard(): 
    user = User.query.get(session['user_id'])
    # Get counts for different query statuses
    queries = SqlQuery.query.filter_by(user_id=user.id).order_by(SqlQuery.created_at.desc()).all()
    
    pending_count = SqlQuery.query.filter_by(user_id=user.id, status='pending')
    approved_count = SqlQuery.query.filter_by(user_id=user.id, status='approved')
    rejected_count = SqlQuery.query.filter_by(user_id=user.id, status='rejected')
    executed_count = SqlQuery.query.filter_by(user_id=user.id, is_executed=True)
    
    # For approvers, get count of pending approvals
    pending_approvals = 0
    if user.role in ['admin', 'approver']:
        pending_approvals = SqlQuery.query.filter_by(status='pending').count()
    return render_template('user_dashboard.html', 
                           user=user, 
                           queries=queries,
                           pending_count=pending_count,
                           approved_count=approved_count,
                           rejected_count=rejected_count,
                           executed_count=executed_count,
                           pending_approvals=pending_approvals)

@app.route('/logout')
def logout():
    session.clear()
    flash('Çıkış yaptınız!', 'info')
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
            flash('Tüm alanlar zorunludur.', 'danger')
            return render_template('create_user.html')
        
        # Check username format (alphanumeric, underscores, 3-20 chars)
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            flash('Kullanıcı adı  3-20 karakter uzunluğunda, sadece harf, rakam ve alt çizgi içerebilir.', 'danger')
            return render_template('create_user.html')
        
        # Check email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash('Lütfen geçerli bir e-posta girin.', 'danger')
            return render_template('create_user.html')
        
        # Check password strength (min 8 chars, 1 uppercase, 1 lowercase, 1 digit)
        if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password):
            flash('Parola en az 8 karakter uzunluğunda olmalı, büyük harf, küçük harf ve sayı içermeli.', 'danger')
            return render_template('create_user.html')
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Kullanıcı adı alınmış.', 'danger')
            return render_template('create_user.html')
        
        if User.query.filter_by(email=email).first():
            flash('Bu e-posta kullanılıyor.', 'danger')
            return render_template('create_user.html')
        
        # Create new user
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash(f'{username} başarıyla oluşturuldu.', 'success')
            return redirect(url_for('user_management'))
        except Exception as e:
            db.session.rollback()
            flash(f'Kullanıcı : {str(e)} oluşturulurken hata aldı. ', 'danger')
            return render_template('create_user.html')
    
    return render_template('create_user.html')

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent editing the currently logged-in admin (for safety)
    if user_id == session.get('user_id'):
        flash('Kendi hesabınızı düzenleyemezsiniz.', 'warning')
        return redirect(url_for('user_management'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        role = request.form.get('role')
        active = 'active' in request.form
        new_password = request.form.get('password')
        
        # Validate email
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash('Geçerli bir e-posta girin.', 'danger')
            return render_template('edit_user.html', user=user)
        
        # Check if email already exists (for a different user)
        existing_user = User.query.filter_by(email=email).first()
        if existing_user and existing_user.id != user_id:
            flash('E-posta başka bir kullanıcı tarafından kullanılıyor.', 'danger')
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

#Sorgular
@app.route('/queries')
@app.route('/queries/<status>')
@login_required
@approver_required
def query_list(status=None):
    """
    Display a list of queries for approvers.
    Optionally filter by status (pending, approved, rejected).
    """
    # Build the query based on status filter
    query = SqlQuery.query
    
    if status:
        query = query.filter_by(status=status)
    
    # Get all queries with the specified status (or all if no status specified)
    queries = query.order_by(SqlQuery.created_at.desc()).all()
    
    return render_template('query_list.html', queries=queries, status=status)

@app.route('/queries/create', methods=['GET', 'POST'])
@login_required
def create_query():
    if request.method == 'POST':
        query_text = request.form.get('query_text')
        description = request.form.get('description')
        
        # Validate inputs
        if not query_text or not description:
            flash('Query text and description are required', 'danger')
            return render_template('create_query.html', query_text=query_text, description=description)
        
        # Basic SQL validation (as in your original code)
        try:
            parsed = sqlparse.parse(query_text)
            if not parsed:
                flash('Invalid SQL query format', 'danger')
                return render_template('create_query.html', query_text=query_text, description=description)
            
            query_upper = query_text.upper()
            dangerous_keywords = ['DROP', 'TRUNCATE', 'DELETE', 'ALTER', 'GRANT', 'REVOKE', 'INSERT', 'UPDATE']
            for keyword in dangerous_keywords:
                if keyword in query_upper and not 'SELECT' in query_upper:
                    flash(f'Potential harmful operation detected: {keyword}. This will require special approval.', 'warning')
                    break
        except Exception as e:
            flash(f'Error validating query: {str(e)}', 'danger')
            return render_template('create_query.html', query_text=query_text, description=description)
        
        # Send to Ollama for analysis
        try:
            import requests
            
            prompt = f"""
            Review the following SQL query based on the given rules
            
            ```sql
            {query_text}
            ```
            
            Context: 
1.All SELECT statements must include NOLOCK after every table name. If missing, highlight the issue.
2.UPDATE and DELETE statements must not be executed without a WHERE clause. If a WHERE clause is present, it must contain a meaningful condition and should not rely solely on equality (=) filtering. Flag any violations.
3.Subqueries must also include NOLOCK for all tables used. Identify missing NOLOCK usages.
4.For UPDATE, INSERT, and DELETE operations, if the transaction is interrupted or killed, it must ensure a session rollback and notify the user. Check if this safeguard is implemented.
5.SELECT INTO statements must not be used, as they can create full table backups or copies. If found, flag it.
6.All SELECT queries must limit the number of rows fetched, even if a WHERE clause is used. A maximum limit, such as TOP 10000, must be enforced. If missing, indicate the issue.
7.If the query involves a table from a predefined list of critical tables, warn the user. The critical table list: [CUSTOMERS, ACCOUNT, NOTIFICATION].
            
            Respond with either "APPROVE" or "REJECT" followed by a brief explanation.
            """
            
            # Call Ollama API
            response = requests.post(
                'http://localhost:11434/api/generate',
                json={
                    "model": "llama3", # or whatever model you prefer
                    "prompt": prompt,
                    "stream": False
                }
            )
            
            llm_response = ""
            approval_recommendation = "pending"
            
            if response.status_code == 200:
                llm_response = response.json().get('response', '')
                
                # Simple parsing of the LLM response
                if "APPROVE" in llm_response.upper():
                    approval_recommendation = "recommended"
                elif "REJECT" in llm_response.upper():
                    approval_recommendation = "not_recommended"
                
                # Store LLM analysis for admin review
                llm_analysis = f"LLM Analysis:\n{llm_response}"
            else:
                llm_analysis = f"LLM analysis failed: {response.text}"
        
        except Exception as e:
            llm_analysis = f"Error analyzing with LLM: {str(e)}"
            approval_recommendation = "pending"
        
        # Create new query with LLM analysis
        new_query = SqlQuery(
            query_text=query_text,
            description=description,
            user_id=session['user_id'],
            status='pending',
            llm_analysis=llm_analysis,
            approval_recommendation=approval_recommendation
        )
        
        try:
            db.session.add(new_query)
            db.session.commit()
            
            if approval_recommendation == "recommended":
                flash('SQL query submitted successfully. LLM recommends approval.', 'success')
            elif approval_recommendation == "not_recommended":
                flash('SQL query submitted. LLM has some concerns. An admin will review.', 'warning')
            else:
                flash('SQL query submitted successfully for approval', 'success')
                
            return redirect(url_for('user_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting query: {str(e)}', 'danger')
            return render_template('create_query.html', query_text=query_text, description=description)
    
    return render_template('create_query.html')
""" #orijinal olan
@app.route('/queries/create', methods=['GET', 'POST'])
@login_required
def create_query():
    if request.method == 'POST':
        query_text = request.form.get('query_text')
        description = request.form.get('description')
        
        # Validate inputs
        if not query_text or not description:
            flash('Query text and description are required', 'danger')
            return render_template('create_query.html', query_text=query_text, description=description)
        
        # Validate SQL query format and check for potentially harmful operations
        try:
            # Parse the SQL query
            parsed = sqlparse.parse(query_text)
            if not parsed:
                flash('Invalid SQL query format', 'danger')
                return render_template('create_query.html', query_text=query_text, description=description)
            
            # Convert to uppercase for easier checking
            query_upper = query_text.upper()
            
            # Check for potentially harmful operations
            dangerous_keywords = ['DROP', 'TRUNCATE', 'DELETE', 'ALTER', 'GRANT', 'REVOKE', 'INSERT', 'UPDATE']
            for keyword in dangerous_keywords:
                if keyword in query_upper and not 'SELECT' in query_upper:
                    flash(f'Potential harmful operation detected: {keyword}. This will require special approval.', 'warning')
                    break
            
        except Exception as e:
            flash(f'Error validating query: {str(e)}', 'danger')
            return render_template('create_query.html', query_text=query_text, description=description)
        
        # Create new query
        new_query = SqlQuery(
            query_text=query_text,
            description=description,
            user_id=session['user_id'],
            status='pending'
        )
        
        try:
            db.session.add(new_query)
            db.session.commit()
            flash('SQL query submitted successfully for approval', 'success')
            return redirect(url_for('user_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting query: {str(e)}', 'danger')
            return render_template('create_query.html', query_text=query_text, description=description)
    
    return render_template('create_query.html')
#burada bitti """

@app.route('/queries/view/<query_id>')
@login_required
def view_query(query_id):
    query = SqlQuery.query.get_or_404(query_id)
    
    # Check access permissions
    user = User.query.get(session['user_id'])
    if query.user_id != user.id and user.role not in ['admin', 'approver']:
        flash('Bu sorguyu görmeye yetkiniz yok!', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Get approver name if available
    approver_name = None
    if query.approved_by:
        approver = User.query.get(query.approved_by)
        if approver:
            approver_name = approver.username
    
    return render_template('review_query.html', query=query, approver_name=approver_name)

@app.route('/queries/approve/<query_id>', methods=['GET', 'POST'])
@login_required
@approver_required
def approve_query(query_id):
    query = SqlQuery.query.get_or_404(query_id)
    
    # Check if query is already approved or rejected
    if query.status != 'pending':
        flash('This query has already been processed', 'warning')
        return redirect(url_for('query_list'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        comments = request.form.get('comments')
        
        if action == 'approve':
            query.status = 'approved'
            query.approved_by = session['user_id']
            query.approval_date = datetime.now()
            query.comments = comments
            
            try:
                db.session.commit()
                flash('Query approved successfully', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error approving query: {str(e)}', 'danger')
                
        elif action == 'reject':
            query.status = 'rejected'
            query.approved_by = session['user_id']
            query.approval_date = datetime.now()
            query.comments = comments
            
            try:
                db.session.commit()
                flash('Query rejected', 'warning')
            except Exception as e:
                db.session.rollback()
                flash(f'Error rejecting query: {str(e)}', 'danger')
        
        return redirect(url_for('query_list', status='pending'))
    
    return render_template('review_query.html', query=query)

@app.route('/queries/execute/<query_id>', methods=['POST'])
@login_required
@approver_required
def execute_query(query_id):
    query = SqlQuery.query.get_or_404(query_id)
    
    # Check if query is approved and not yet executed
    if query.status != 'approved':
        flash('Only approved queries can be executed', 'warning')
        return redirect(url_for('view_query', query_id=query_id))
    
    if query.is_executed:
        flash('This query has already been executed', 'warning')
        return redirect(url_for('view_query', query_id=query_id))
    
    try:
        # Create a separate connection to execute the query
        with db.engine.connect() as connection:
            # Execute the query
            result = connection.execute(text(query.query_text))
            
            # Format the result for display
            if result.returns_rows:
                # Get column names
                columns = result.keys()
                
                # Get all rows
                rows = result.fetchall()
                
                # Format as HTML table
                result_html = '<table class="table table-striped">\n<thead>\n<tr>\n'
                for column in columns:
                    result_html += f'<th>{column}</th>\n'
                result_html += '</tr>\n</thead>\n<tbody>\n'
                
                for row in rows:
                    result_html += '<tr>\n'
                    for cell in row:
                        result_html += f'<td>{cell}</td>\n'
                    result_html += '</tr>\n'
                
                result_html += '</tbody>\n</table>'
                
                # Store in the database
                result_text = f"Query executed successfully. {len(rows)} rows returned.\n\n{result_html}"
            else:
                # No rows returned (e.g., for DDL/DML statements)
                result_text = "Query executed successfully. No rows returned."
        
        # Update query record
        query.is_executed = True
        query.execution_date = datetime.now()
        query.execution_result = result_text
        
        db.session.commit()
        flash('Query executed successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error executing query: {str(e)}', 'danger')
    
    return redirect(url_for('view_query', query_id=query_id))

# AJAX route for SQL validation
@app.route('/validate-sql', methods=['POST'])
@login_required
def validate_sql():
    query_text = request.form.get('query')
    
    if not query_text:
        return jsonify({'valid': False, 'message': 'Query is empty'})
    
    try:
        # Parse the SQL query
        parsed = sqlparse.parse(query_text)
        if not parsed:
            return jsonify({'valid': False, 'message': 'Invalid SQL query format'})
        
        # Check query type
        stmt = parsed[0]
        stmt_type = stmt.get_type()
        
        # Convert to uppercase for easier checking
        query_upper = query_text.upper()
        
        # Check for potentially harmful operations
        dangerous_keywords = ['DROP', 'TRUNCATE', 'DELETE', 'ALTER', 'GRANT', 'REVOKE']
        for keyword in dangerous_keywords:
            if keyword in query_upper:
                return jsonify({
                    'valid': True, 
                    'warning': True,
                    'message': f'Warning: {keyword} operation detected. This will require special approval.'
                })
        
        # Check for data modification statements
        if 'INSERT' in query_upper or 'UPDATE' in query_upper:
            return jsonify({
                'valid': True,
                'warning': True,
                'message': 'Warning: Data modification statement detected. This will require special approval.'
            })
        
        return jsonify({'valid': True, 'message': 'Query format is valid'})
        
    except Exception as e:
        return jsonify({'valid': False, 'message': f'Error validating query: {str(e)}'})

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
    app.run(debug=True)  # Set to False in production
