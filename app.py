from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, Regexp
import re
from datetime import timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///firstapp.db"
app.config['SECRET_KEY'] = 'your-very-secure-secret-key-change-in-production-2024'
app.config['WTF_CSRF_SECRET_KEY'] = 'different-csrf-secret-key-2024'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize extensions - IMPORTANT: Do this BEFORE models
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

# Custom validators
def sanitize_input(input_string):
    """Sanitize input to prevent XSS and SQL injection"""
    if not input_string:
        return input_string
    sanitized = re.sub(r'[<>&\"\';]', '', input_string)
    return sanitized[:500]

def validate_sql_injection_free(input_string):
    """Check for common SQL injection patterns"""
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'OR', 'AND']
    input_upper = input_string.upper()
    for keyword in sql_keywords:
        if re.search(r'\b' + re.escape(keyword) + r'\b', input_upper):
            return False
    return True

# WTForms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=80),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username can only contain letters, numbers and underscores")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long"),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)', 
              message="Password must contain at least one uppercase letter, one lowercase letter and one number")
    ])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=80)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=1, message="Password is required")
    ])

class ContactForm(FlaskForm):
    phone = StringField('Phone', validators=[
        DataRequired(),
        Length(min=10, max=20),
        Regexp(r'^[\d\s\-\+\(\)]+$', message="Phone number can only contain digits, spaces, and -+()")
    ])
    address = TextAreaField('Address', validators=[
        DataRequired(),
        Length(min=5, max=500),
        Regexp(r'^[a-zA-Z0-9\s\-\.,#]+$', message="Address contains invalid characters")
    ])
    city = StringField('City', validators=[
        DataRequired(),
        Length(min=2, max=100),
        Regexp(r'^[a-zA-Z\s\-]+$', message="City can only contain letters, spaces and hyphens")
    ])
    country = StringField('Country', validators=[
        DataRequired(),
        Length(min=2, max=100),
        Regexp(r'^[a-zA-Z\s\-]+$', message="Country can only contain letters, spaces and hyphens")
    ])

# Database Models - MUST be defined AFTER bcrypt initialization
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    def set_password(self, password):
        # Force bcrypt hashing
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    city = db.Column(db.String(100))
    country = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=db.func.now())

# Database cleanup - Delete all existing users to force bcrypt
with app.app_context():
    db.create_all()
    
    # Delete ALL existing users to ensure bcrypt is used
    existing_users = User.query.all()
    for user in existing_users:
        db.session.delete(user)
        print(f"Deleted user with scrypt hash: {user.username}")
    
    if existing_users:
        db.session.commit()
        print(f"Cleaned up {len(existing_users)} users. New registrations will use bcrypt.")

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

# Routes
@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect('/contact')
    
    form = LoginForm()
    
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        password = form.password.data
        
        if not validate_sql_injection_free(username):
            flash('Invalid input detected', 'error')
            return render_template('login.html', form=form)
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect('/contact')
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect('/login')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if 'user_id' not in session:
        flash('Please login to access contact form', 'error')
        return redirect('/login')
    
    form = ContactForm()
    contact_info = Contact.query.filter_by(user_id=session['user_id']).first()
    
    if contact_info and request.method == 'GET':
        form.phone.data = contact_info.phone
        form.address.data = contact_info.address
        form.city.data = contact_info.city
        form.country.data = contact_info.country
    
    if form.validate_on_submit():
        phone = sanitize_input(form.phone.data)
        address = sanitize_input(form.address.data)
        city = sanitize_input(form.city.data)
        country = sanitize_input(form.country.data)
        
        for field in [phone, address, city, country]:
            if not validate_sql_injection_free(str(field)):
                flash('Invalid input detected in one or more fields', 'error')
                return render_template('contact.html', form=form)
        
        existing_contact = Contact.query.filter_by(user_id=session['user_id']).first()
        
        if existing_contact:
            existing_contact.phone = phone
            existing_contact.address = address
            existing_contact.city = city
            existing_contact.country = country
            flash('Contact details updated successfully!', 'success')
        else:
            new_contact = Contact(
                user_id=session['user_id'],
                phone=phone,
                address=address,
                city=city,
                country=country
            )
            db.session.add(new_contact)
            flash('Contact details saved successfully!', 'success')
        
        db.session.commit()
        return redirect('/contact')
    
    return render_template('contact.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect('/contact')
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        password = form.password.data
        
        if not validate_sql_injection_free(username):
            flash('Invalid input detected', 'error')
            return render_template('register.html', form=form)
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html', form=form)
        else:
            new_user = User(username=username)
            new_user.set_password(password)  # This will use bcrypt
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect('/login')
    
    return render_template('register.html', form=form)

if __name__ == "__main__":
    app.run(debug=True)