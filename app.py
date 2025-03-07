from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import random
from itsdangerous import URLSafeTimedSerializer
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:21044WdhK@localhost/capstone'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Unauthorized handler: if not logged in, redirect to a custom unauthorized page
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('unauthorized'))

# -------------------- Models -----------------------____
class Users(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default="user", nullable=False)
    balance = db.Column(db.Float, default=0.0)  


class Stock(db.Model):
    __tablename__ = 'stocks'
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(10), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False, default=1.00)
    sector = db.Column(db.String(100), nullable=True)
    price_change = db.Column(db.Float, nullable=False, default=0.00)  
    percent_change = db.Column(db.Float, nullable=False, default=0.00)  



    def update_price(self):
        change_percentage = random.uniform(-5, 5)  # Change between -10% and +10%
        change_amount = round(self.price * (change_percentage / 100), 2)
        
        self.price = round(self.price + change_amount, 2)
        self.price_change = change_amount
        self.percent_change = round(change_percentage, 2)

        if self.price < 1:  # Prevent stock price from dropping to zero or negative
            self.price = 1.00


class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stocks.id'), nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.Enum('buy', 'sell'), nullable=False)
    transaction_date = db.Column(db.DateTime, server_default=db.func.current_timestamp())

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# -------------------- Password Reset Functions --------------------
def generate_reset_token(email, salt='password-reset-salt'):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=salt)

def verify_reset_token(token, expiration=3600, salt='password-reset-salt'):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=salt, max_age=expiration)
    except Exception:
        return None
    return email

@app.template_filter('currency')
def currency_format(value):
    try:
        return "${:,.2f}".format(float(value))
    except (ValueError, TypeError):
        return value

# -------------------- Routes --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if Users.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        if Users.query.filter_by(email=email).first():
            flash('Email already registered. Please use a different email.', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = Users(fullname=fullname, username=username, email=email, password=hashed_password, role="user")
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = Users.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f'Welcome, {user.fullname}!', 'success')
            return redirect(url_for('portfolio'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/')
def home():
    return render_template('home.html', current_user=current_user)

@app.route('/about')
def about():
    return render_template('about.html', title='About')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        flash(f'Thank you {name}, we have received your message!', 'success')
        return redirect(url_for('home'))
    return render_template('contact.html', title='Contact')

# -------------------- Password Reset Routes --------------------
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form.get('email')
        user = Users.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(email)
            flash('A password reset link has been sent to your email. (For demo, you are being redirected.)', 'info')
            return redirect(url_for('reset_token', token=token))
        else:
            flash('No account found with that email.', 'danger')
            return redirect(url_for('login'))
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    email = verify_reset_token(token)
    if not email:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('reset_request'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('reset_token', token=token))
        user = Users.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Your password has been updated. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_token.html', token=token)
# -------------------- End Password Reset Routes --------------------

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for("unauthorized"))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/unauthorized')
def unauthorized():
    return render_template('unauthorized.html'), 403

# -------------------- Other Routes --------------------
@app.route('/admin')
@login_required
@admin_required
def admin():
    users = Users.query.all()
    stocks = Stock.query.all()  # Ensure stocks are retrieved
    return render_template("admin.html", users=users, stocks=stocks)

@app.route('/delete-user/<int:user_id>', methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    user = Users.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin'))

@app.route('/change-role/<int:user_id>', methods=["POST"])
@login_required
@admin_required
def change_role(user_id):
    user = Users.query.get_or_404(user_id)
    new_role = request.form.get("role")
    if new_role in ["user", "admin"]:
        user.role = new_role
        db.session.commit()
        flash('User role updated successfully.', 'success')
    return redirect(url_for('admin'))

# In app.py

@app.route('/portfolio')
@login_required
def portfolio():
    user_transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    user = Users.query.get(current_user.id)

    holdings = {}
    total_shares = 0
    total_value = 0.0

    for tx in user_transactions:
        stock = Stock.query.get(tx.stock_id)
        if not stock:
            continue  # Skip if stock doesn't exist

        # Initialize the holding if not already present
        if stock.id not in holdings:
            holdings[stock.id] = {
                "symbol": stock.symbol,
                "shares": 0,
                "total_cost": 0.0,
                "sector": stock.sector if stock.sector else "N/A",
                "price_change": float(stock.price_change) if stock.price_change is not None else 0.0,
                "percent_change": float(stock.percent_change) if stock.percent_change is not None else 0.0,
                "current_price": float(stock.price) if stock.price is not None else 0.0
            }

        if tx.transaction_type == 'buy':
            holdings[stock.id]["shares"] += tx.shares
            holdings[stock.id]["total_cost"] += tx.shares * stock.price
            total_shares += tx.shares
        elif tx.transaction_type == 'sell':
            holdings[stock.id]["shares"] -= tx.shares
            holdings[stock.id]["total_cost"] -= tx.shares * stock.price
            total_shares -= tx.shares

        # Remove holdings if shares drop to zero or below
        if holdings.get(stock.id, {}).get("shares", 0) <= 0:
            holdings.pop(stock.id, None)

    # Calculate total portfolio value
    for data in holdings.values():
        total_value += data["shares"] * data["current_price"]

    portfolio_data = {
        "total_value": round(total_value, 2),
        "num_stocks": len(holdings),
        "total_shares": total_shares,
        "balance": round(user.balance, 2) if user.balance is not None else 0.0,
        "holdings": holdings
    }

    return render_template('portfolio.html', portfolio_data=portfolio_data)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        user = Users.query.get(current_user.id)
        user.fullname = fullname
        user.email = email
        db.session.commit()
        flash('Profile updated successfully.', 'success')
    return render_template('profile.html', title='Profile', user=current_user)

@app.route('/transactions')
@login_required
def transactions():
    user_transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.transaction_date.desc()).all()
    
    transactions_list = []  # ✅ Ensure transactions_list is defined before usage

    for tx in user_transactions:
        stock = Stock.query.get(tx.stock_id)
        if stock:
            transactions_list.append({
                "symbol": stock.symbol,
                "transaction_type": tx.transaction_type,
                "shares": tx.shares,
                "price": tx.price,
                "transaction_date": tx.transaction_date
            })

    # ✅ Ensure total_value is calculated correctly
    holdings = {}
    total_value = 0.0

    for tx in user_transactions:
        sid = tx.stock_id
        if sid not in holdings:
            holdings[sid] = {"shares": 0, "total_cost": 0.0}

        if tx.transaction_type == 'buy':
            holdings[sid]["shares"] += tx.shares
            holdings[sid]["total_cost"] += tx.shares * tx.price
        elif tx.transaction_type == 'sell':
            holdings[sid]["shares"] -= tx.shares
            holdings[sid]["total_cost"] -= tx.shares * tx.price

    for sid, data in holdings.items():
        if data["shares"] > 0:
            stock = Stock.query.get(sid)  # ✅ Ensure stock is fetched correctly
            if stock:
                total_value += data["shares"] * stock.price  # ✅ Use stock.price instead of undefined variable

    return render_template('transactions.html', title='Transactions', transactions=transactions_list, total_value=round(total_value, 2))

@app.route('/add-funds', methods=['POST'])
@login_required
def add_funds():
    try:
        amount = float(request.form.get('amount'))
    except ValueError:
        flash('Invalid amount entered.', 'danger')
        return redirect(url_for('portfolio'))

    if amount <= 0:
        flash('Please enter a positive amount.', 'danger')
        return redirect(url_for('portfolio'))

    current_user.balance += amount  # Update the user's balance
    db.session.commit()

    flash(f"Successfully added ${amount:,.2f} to your account.", "success")
    return redirect(url_for('portfolio'))

import random
from flask import render_template

@app.route('/stocks')
@login_required
def stocks():
    stocks_query = Stock.query.all()
    for stock in stocks_query:
        # Ensure the current price is valid; default to $1.00 if missing or <= 0
        try:
            current_price = float(stock.price)
        except (TypeError, ValueError):
            current_price = 1.00
        if current_price <= 0:
            current_price = 1.00

        # Simulate a fluctuation between -10% and +10%
        change_percentage = random.uniform(-10, 10)
        change_amount = round(current_price * (change_percentage / 100), 2)
        new_price = round(current_price + change_amount, 2)
        if new_price < 1:
            new_price = 1.00

        # Update the stock object
        stock.price = new_price
        stock.price_change = change_amount
        stock.percent_change = round(change_percentage, 2)

    # Commit these simulated updates so that the updated price is stored in the DB.
    db.session.commit()

    stocks_list = [
        {
            "id": stock.id,
            "symbol": stock.symbol,
            "name": stock.name,
            "price": stock.price,  # a float value, e.g., 123.45
            "price_change": stock.price_change if stock.price_change is not None else 0.00,
            "percent_change": stock.percent_change if stock.percent_change is not None else 0.00,
            "sector": stock.sector if stock.sector else "N/A"
        }
        for stock in stocks_query
    ]
    return render_template('stocks.html', stocks=stocks_list)

@app.route('/buy-stock/<int:stock_id>', methods=['POST'])
@login_required
def buy_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)

    try:
        shares = int(request.form.get("shares"))
    except (ValueError, TypeError):
        flash("Invalid input. Please enter a valid number of shares.", "danger")
        return redirect(url_for("stocks"))

    if shares <= 0:
        flash("You must buy at least one share.", "danger")
        return redirect(url_for("stocks"))

    # ✅ Fix: Remove initial_price and use stock.price
    price = round(random.uniform(stock.price * 0.9, stock.price * 1.1), 2)
    total_cost = round(price * shares, 2)

    user = Users.query.get(current_user.id)

    if user.balance < total_cost:
        flash(f"Insufficient funds! You need ${total_cost:.2f} but only have ${user.balance:.2f}.", "danger")
        return redirect(url_for("stocks"))

    user.balance -= total_cost

    new_transaction = Transaction(
        user_id=user.id,
        stock_id=stock.id,
        shares=shares,
        price=price,
        transaction_type="buy"
    )

    db.session.add(new_transaction)
    db.session.commit()

    flash(f"Bought {shares} shares of {stock.name} at ${price:.2f} per share!", "success")
    return redirect(url_for("transactions"))

@app.route('/sell-stock/<int:stock_id>', methods=['GET', 'POST'])
@login_required
def sell_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)

    total_buys = db.session.query(db.func.sum(Transaction.shares)).filter_by(user_id=current_user.id, stock_id=stock.id, transaction_type='buy').scalar() or 0
    total_sells = db.session.query(db.func.sum(Transaction.shares)).filter_by(user_id=current_user.id, stock_id=stock.id, transaction_type='sell').scalar() or 0
    holdings = total_buys - total_sells

    try:
        shares = int(request.form.get('shares'))
    except ValueError:
        flash('Invalid input. Enter a valid number of shares.', 'danger')
        return redirect(url_for('stocks'))

    if shares <= 0:
        flash('Number of shares must be positive.', 'danger')
        return redirect(url_for('stocks'))

    if shares > holdings:
        flash(f'Insufficient shares. You own {holdings} shares.', 'danger')
        return redirect(url_for('stocks'))

    price = round(random.uniform(stock.initial_price * 0.9, stock.initial_price * 1.1), 2)
    new_transaction = Transaction(user_id=current_user.id, stock_id=stock.id, shares=shares, price=price, transaction_type='sell')

    db.session.add(new_transaction)
    db.session.commit()
    flash(f'Sold {shares} shares of {stock.name} at ${price} per share!', 'success')
    return redirect(url_for('transactions'))


@app.route('/create-stock', methods=['POST'])
@login_required
@admin_required
def create_stock():
    symbol = request.form.get('symbol').upper()
    stock_name = request.form.get('name')
    price = float(request.form.get('price'))
    sector = request.form.get('sector')  # Allow selecting a sector

    # Ensure stock symbol is unique
    existing_stock = Stock.query.filter_by(symbol=symbol).first()
    if existing_stock:
        flash('Stock symbol already exists!', 'danger')
        return redirect(url_for('admin'))

    new_stock = Stock(
        symbol=symbol,
        name=stock_name,
        price=price,
        sector=sector
    )

    db.session.add(new_stock)
    db.session.commit()
    flash('Stock created successfully!', 'success')
    return redirect(url_for('admin'))


@app.route('/delete-stock/<int:stock_id>', methods=['POST'])
@login_required
@admin_required
def delete_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)

    # Prevent deletion if transactions exist for this stock
    transaction_exists = Transaction.query.filter_by(stock_id=stock.id).first()
    if transaction_exists:
        flash('Cannot delete stock with existing transactions.', 'danger')
        return redirect(url_for('admin'))

    db.session.delete(stock)
    db.session.commit()
    flash(f'Stock {stock.symbol} deleted successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/edit-stock/<int:stock_id>', methods=['POST'])
@login_required
@admin_required
def edit_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)

    stock.name = request.form['name']
    stock.price = float(request.form['price'])
    stock.sector = request.form['sector']

    db.session.commit()
    flash(f'Stock {stock.symbol} updated successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/deposit_funds', methods=['POST'])
@login_required
def deposit_funds():
    try:
        amount = float(request.form.get('deposit_amount'))
        if amount <= 0:
            flash('Deposit amount must be greater than zero.', 'danger')
        else:
            current_user.balance += amount
            db.session.commit()
            flash(f'Successfully deposited ${amount:,.2f}!', 'success')
    except ValueError:
        flash('Invalid input. Please enter a valid number.', 'danger')
    return redirect(url_for('portfolio'))


@app.route('/withdraw_funds', methods=['POST'])
@login_required
def withdraw_funds():
    try:
        amount = float(request.form.get('withdraw_amount'))
        if amount <= 0:
            flash('Withdrawal amount must be greater than zero.', 'danger')
        elif amount > current_user.balance:
            flash(f'Insufficient funds. Your balance is ${current_user.balance:,.2f}.', 'danger')
        else:
            current_user.balance -= amount
            db.session.commit()
            flash(f'Successfully withdrew ${amount:,.2f}!', 'success')
    except ValueError:
        flash('Invalid input. Please enter a valid number.', 'danger')
    return redirect(url_for('portfolio'))

if __name__ == '__main__':
    app.run(debug=True)