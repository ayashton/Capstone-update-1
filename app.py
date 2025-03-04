from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import random
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:21044WdhK@localhost/capstone'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Unauthorized handler: if not logged in, redirect to a custom unauthorized page
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('unauthorized'))

# -------------------- Models --------------------
class Users(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default="user", nullable=False)

class Stock(db.Model):
    __tablename__ = 'stocks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    initial_price = db.Column(db.Float, nullable=False)

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
    return render_template("admin.html", users=users)

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

@app.route('/portfolio')
@login_required
def portfolio():
    user_transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    holdings = {}
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
    portfolio_holdings = []
    total_value = 0.0
    for sid, data in holdings.items():
        if data["shares"] > 0:
            stock = Stock.query.get(sid)
            avg_price = data["total_cost"] / data["shares"] if data["shares"] else 0
            value = data["shares"] * avg_price
            total_value += value
            portfolio_holdings.append({
                "symbol": stock.name.upper()[:4],
                "shares": data["shares"],
                "avg_price": round(avg_price, 2),
                "total_value": round(value, 2)
            })
    portfolio_data = {
        "total_value": round(total_value, 2),
        "cash": 0.00,
        "num_stocks": len(portfolio_holdings),
        "holdings": portfolio_holdings
    }
    return render_template('portfolio.html', title='Portfolio', portfolio_data=portfolio_data)

@app.route('/transactions')
@login_required
def transactions():
    txs = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.transaction_date.desc()).all()
    transactions_list = []
    for tx in txs:
        stock = Stock.query.get(tx.stock_id)
        transactions_list.append({
            "symbol": stock.name.upper()[:4],
            "transaction_type": tx.transaction_type,
            "shares": tx.shares,
            "price": tx.price,
            "transaction_date": tx.transaction_date
        })
    # Recalculate total account value from holdings.
    user_transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    holdings = {}
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
    total_value = 0.0
    for sid, data in holdings.items():
        if data["shares"] > 0:
            avg_price = data["total_cost"] / data["shares"]
            total_value += data["shares"] * avg_price
    return render_template('transactions.html', title='Transactions', transactions=transactions_list, total_value=round(total_value, 2))

@app.route('/stocks')
@login_required
def stocks():
    stocks_query = Stock.query.all()
    stocks_list = []
    if stocks_query:
        for stock in stocks_query:
            price = round(random.uniform(stock.initial_price * 0.9, stock.initial_price * 1.1), 2)
            symbol = stock.name.upper()[:4]
            stocks_list.append({"id": stock.id, "symbol": symbol, "name": stock.name, "price": price})
    else:
         stocks_list = [
             {"id": 1, "symbol": "AAPL", "name": "Apple Inc.", "price": round(random.uniform(140, 160), 2)},
             {"id": 2, "symbol": "GOOGL", "name": "Alphabet Inc.", "price": round(random.uniform(2500, 2800), 2)},
             {"id": 3, "symbol": "AMZN", "name": "Amazon.com Inc.", "price": round(random.uniform(3300, 3500), 2)},
         ]
    return render_template('stocks.html', title='Stocks', stocks=stocks_list)

@app.route('/buy-stock/<int:stock_id>', methods=["GET", "POST"])
@login_required
def buy_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)
    if request.method == "POST":
        try:
            shares = int(request.form.get("shares"))
        except (ValueError, TypeError):
            flash("Please enter a valid number of shares.", "danger")
            return redirect(url_for('buy_stock', stock_id=stock_id))
        if shares <= 0:
            flash("Number of shares must be positive.", "danger")
            return redirect(url_for('buy_stock', stock_id=stock_id))
        price = round(random.uniform(stock.initial_price * 0.9, stock.initial_price * 1.1), 2)
        new_transaction = Transaction(user_id=current_user.id, stock_id=stock.id, shares=shares, price=price, transaction_type="buy")
        db.session.add(new_transaction)
        db.session.commit()
        flash(f'Bought {shares} shares of {stock.name} at ${price} per share!', 'success')
        return redirect(url_for("transactions"))
    return render_template("buy_stock.html", stock=stock)

@app.route('/sell-stock/<int:stock_id>', methods=["GET", "POST"])
@login_required
def sell_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)
    buys = db.session.query(db.func.sum(Transaction.shares)).filter_by(user_id=current_user.id, stock_id=stock.id, transaction_type="buy").scalar() or 0
    sells = db.session.query(db.func.sum(Transaction.shares)).filter_by(user_id=current_user.id, stock_id=stock.id, transaction_type="sell").scalar() or 0
    holding = buys - sells
    if request.method == "POST":
        try:
            shares = int(request.form.get("shares"))
        except (ValueError, TypeError):
            flash("Please enter a valid number of shares.", "danger")
            return redirect(url_for('sell_stock', stock_id=stock_id))
        if shares <= 0:
            flash("Number of shares must be positive.", "danger")
            return redirect(url_for('sell_stock', stock_id=stock_id))
        if shares > holding:
            flash(f"You do not have enough shares to sell. You currently hold {holding} shares.", "danger")
            return redirect(url_for('sell_stock', stock_id=stock_id))
        price = round(random.uniform(stock.initial_price * 0.9, stock.initial_price * 1.1), 2)
        new_transaction = Transaction(user_id=current_user.id, stock_id=stock.id, shares=shares, price=price, transaction_type="sell")
        db.session.add(new_transaction)
        db.session.commit()
        flash(f'Sold {shares} shares of {stock.name} at ${price} per share!', 'success')
        return redirect(url_for("transactions"))
    return render_template("sell_stock.html", stock=stock, holding=holding)

@app.route('/create-stock', methods=["POST"])
@login_required
@admin_required
def create_stock():
    stock_name = request.form.get('stock_name')
    initial_price = request.form.get('initial_price')
    new_stock = Stock(name=stock_name, initial_price=initial_price)
    db.session.add(new_stock)
    db.session.commit()
    flash('Stock created successfully!', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)
