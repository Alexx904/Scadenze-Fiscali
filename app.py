from flask import Flask, request, jsonify, redirect, url_for
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime

import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    company_name = db.Column(db.String(150), nullable=True)
    vat_number = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'Admin', 'Commercialista', 'Studio Commercialista'

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    surname_company_name = db.Column(db.String(150), nullable=False)
    tax_code_vat_number = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    phone = db.Column(db.String(50), nullable=True)
    address = db.Column(db.String(250), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    postal_code = db.Column(db.String(20), nullable=True)
    province = db.Column(db.String(50), nullable=True)

class Deadline(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    notify_1_day = db.Column(db.Boolean, default=False)
    notify_7_days = db.Column(db.Boolean, default=False)
    notify_15_days = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                return jsonify({'message': 'Unauthorized'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

import logging
logging.basicConfig(level=logging.INFO)

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        logging.info(f"Received registration data: {data}")
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        new_user = User(
            first_name=data['first_name'],
            last_name=data['last_name'],
            company_name=data.get('company_name'),
            vat_number=data['vat_number'],
            email=data['email'],
            password=hashed_password,
            role=data['role']
        )
        db.session.add(new_user)
        db.session.commit()
        logging.info("User registered successfully")
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        logging.error(f"Error during registration: {e}")
        return jsonify({'message': 'An error occurred during registration.'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify({'message': 'Logged in successfully', 'role': user.role}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/clients', methods=['POST'])
@login_required
def add_client():
    data = request.get_json()
    new_client = Client(
        user_id=current_user.id,
        name=data['name'],
        surname_company_name=data['surname_company_name'],
        tax_code_vat_number=data['tax_code_vat_number'],
        email=data['email'],
        phone=data.get('phone'),
        address=data.get('address'),
        city=data.get('city'),
        postal_code=data.get('postal_code'),
        province=data.get('province')
    )
    db.session.add(new_client)
    db.session.commit()
    return jsonify({'message': 'Client added successfully'}), 201

@app.route('/clients', methods=['GET'])
@login_required
def get_clients():
    clients = Client.query.filter_by(user_id=current_user.id).all()
    clients_data = []
    for client in clients:
        clients_data.append({
            'id': client.id,
            'name': client.name,
            'surname_company_name': client.surname_company_name,
            'tax_code_vat_number': client.tax_code_vat_number,
            'email': client.email,
            'phone': client.phone,
            'address': client.address,
            'city': client.city,
            'postal_code': client.postal_code,
            'province': client.province
        })
    return jsonify(clients_data), 200

@app.route('/clients/<int:client_id>', methods=['PUT'])
@login_required
def update_client(client_id):
    client = Client.query.get_or_404(client_id)
    if client.user_id != current_user.id:
        return jsonify({'message': 'Unauthorized'}), 403
    data = request.get_json()
    client.name = data['name']
    client.surname_company_name = data['surname_company_name']
    client.tax_code_vat_number = data['tax_code_vat_number']
    client.email = data['email']
    client.phone = data.get('phone')
    client.address = data.get('address')
    client.city = data.get('city')
    client.postal_code = data.get('postal_code')
    client.province = data.get('province')
    db.session.commit()
    return jsonify({'message': 'Client updated successfully'}), 200

@app.route('/clients/<int:client_id>', methods=['DELETE'])
@login_required
def delete_client(client_id):
    client = Client.query.get_or_404(client_id)
    if client.user_id != current_user.id:
        return jsonify({'message': 'Unauthorized'}), 403
    db.session.delete(client)
    db.session.commit()
    return jsonify({'message': 'Client deleted successfully'}), 200

@app.route('/deadlines', methods=['POST'])
@login_required
def add_deadline():
    data = request.get_json()
    new_deadline = Deadline(
        client_id=data['client_id'],
        name=data['name'],
        due_date=datetime.strptime(data['due_date'], '%Y-%m-%d').date(),
        notify_1_day=data.get('notify_1_day', False),
        notify_7_days=data.get('notify_7_days', False),
        notify_15_days=data.get('notify_15_days', False)
    )
    db.session.add(new_deadline)
    db.session.commit()
    return jsonify({'message': 'Deadline added successfully'}), 201

@app.route('/deadlines', methods=['GET'])
@login_required
def get_deadlines():
    deadlines = Deadline.query.join(Client).filter(Client.user_id == current_user.id).all()
    deadlines_data = []
    for deadline in deadlines:
        deadlines_data.append({
            'id': deadline.id,
            'client_id': deadline.client_id,
            'name': deadline.name,
            'due_date': deadline.due_date.strftime('%Y-%m-%d'),
            'notify_1_day': deadline.notify_1_day,
            'notify_7_days': deadline.notify_7_days,
            'notify_15_days': deadline.notify_15_days
        })
    return jsonify(deadlines_data), 200

@app.route('/deadlines/<int:deadline_id>', methods=['PUT'])
@login_required
def update_deadline(deadline_id):
    deadline = Deadline.query.get_or_404(deadline_id)
    client = Client.query.get_or_404(deadline.client_id)
    if client.user_id != current_user.id:
        return jsonify({'message': 'Unauthorized'}), 403
    data = request.get_json()
    deadline.name = data['name']
    deadline.due_date = datetime.strptime(data['due_date'], '%Y-%m-%d').date()
    deadline.notify_1_day = data.get('notify_1_day', False)
    deadline.notify_7_days = data.get('notify_7_days', False)
    deadline.notify_15_days = data.get('notify_15_days', False)
    db.session.commit()
    return jsonify({'message': 'Deadline updated successfully'}), 200

@app.route('/deadlines/<int:deadline_id>', methods=['DELETE'])
@login_required
def delete_deadline(deadline_id):
    deadline = Deadline.query.get_or_404(deadline_id)
    client = Client.query.get_or_404(deadline.client_id)
    if client.user_id != current_user.id:
        return jsonify({'message': 'Unauthorized'}), 403
    db.session.delete(deadline)
    db.session.commit()
    return jsonify({'message': 'Deadline deleted successfully'}), 200

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'Admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'Commercialista':
        return redirect(url_for('commercialista_dashboard'))
    elif current_user.role == 'Studio Commercialista':
        return redirect(url_for('studio_commercialista_dashboard'))
    return jsonify({'message': 'Invalid role'}), 403

@app.route('/admin/dashboard')
@login_required
@role_required('Admin')
def admin_dashboard():
    return send_from_directory('.', 'dashboard_admin.html')

@app.route('/commercialista/dashboard')
@login_required
@role_required('Commercialista')
def commercialista_dashboard():
    return send_from_directory('.', 'dashboard_commercialista_autonomo.html')

from flask import send_from_directory

@app.route('/studio/dashboard')
@login_required
@role_required('Studio Commercialista')
def studio_commercialista_dashboard():
    return send_from_directory('.', 'dashboard_studio_di_commercialisti.html')

@app.route('/<path:filename>')
def serve_html(filename):
    return send_from_directory('.', filename)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)