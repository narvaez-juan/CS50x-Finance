import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, is_safe_password

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user = session["user_id"]
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user)[0]["cash"]
    total = cash

    stocks = db.execute(
        "SELECT symbol, SUM(shares) as sshares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING sshares > 0",
        user,
    )

    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["total"] = stock["price"] * stock["sshares"]
        total += stock["total"]

    return render_template("index.html", stocks=stocks, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stock = lookup(symbol)

        try:
            int_shares = int(shares)
        except ValueError:
            return apology("Shares must be an integer")
        if not symbol:
            return apology("Missing symbol")
        elif stock == None:
            return apology("Symbol does not exist")
        elif not shares:
            return apology("Missing shares")
        elif int_shares != shares or shares <= 0:
            return apology("Shares must be a positive integer")

        symbol = stock["symbol"]
        shares = int_shares
        user_id = session["user_id"]
        price = stock["price"]
        total_cost = price * shares
        user_cash = db.execute("SELECT cash FROM users WHERE user = ?", user_id)[0]["cash"]

        if user_cash < total_cost:
            return apology("Cannot afford shares at the current price")
        else:
            updated_cash = user_cash - total_cost
            db.execute("UPDATE users SET cash = ? WHERE id = ?", updated_cash, user_id)
            db.execute(
                "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                user_id, symbol, shares, price
            )

            flash(f"Bought {shares} shares of {symbol} for {usd(total_cost)}!")
            return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    user = session["user_id"]
    transactions = db.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC", user
    )

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        quotes = lookup(symbol)

        if not symbol:
            return apology("missing symbol")
        elif quotes == None:
            return apology("symbol does not exist")
        else:
            return render_template("quote.html", quotes=quotes)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        usernames = db.execute("SELECT * FROM users WHERE username = ?", username)

        if not username:
            return apology("must provide username")

        elif len(usernames) != 0:
            return apology("username already exist")

        elif not password:
            return apology("must provide password")

        elif password != confirmation:
            return apology("passwords must match")

        elif not is_safe_password(password):
            return apology(
                "new password must contain at least 8 characters, letters and digits"
            )

        else:
            hashed_pw = generate_password_hash(password)

            new_user = db.execute(
                "INSERT INTO users (username, hash) VALUES(?, ?)", username, hashed_pw
            )

            session["user_id"] = new_user

    else:
        return render_template("register.html")

    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session["user_id"]

    if request.method == "GET":
        symbols = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0",
            user_id,
        )
        symbols = [row["symbol"] for row in symbols]
        return render_template("sell.html", symbols=symbols)

    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        quote = lookup(symbol)

        try:
            int_shares = int(shares)
        except ValueError:
            return apology("Shares must be an integer")
        if not symbol:
            return apology("Missing symbol")
        elif quote == None:
            return apology("Symbol does not exist")
        elif not shares:
            return apology("Missing shares")
        elif int_shares != shares or shares <= 0:
            return apology("Shares must be a positive integer")

        shares = int_shares
        stock = db.execute(
            "SELECT symbol, SUM(shares) AS shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol HAVING shares > 0",
            user_id, symbol,
        )

        if stock[0]["shares"] < shares:
            return apology("Too many shares")
        else:
            price = quote["price"]
            total = price * shares
            cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
            updated_cash = cash + total

            db.execute("UPDATE users SET cash = ? WHERE id = ?", updated_cash, user_id)
            db.execute(
                "INSERT INTO transactions (user_id, symbol, shares, price) VALUES(?, ?, ?, ?)",
                user_id,
                symbol,
                -(shares),
                price,
            )

        flash(f"Sold {shares} shares of {symbol} for {usd(total)}")
        return redirect("/")



@app.route("/add", methods=["GET", "POST"])
@login_required
def cash():
    if request.method == "POST":
        user = session["user_id"]

        if not request.form.get("cash"):
            return apology("missing cash")

        add_cash = float(request.form.get("cash"))

        if add_cash <= 0:
            return apology("cash must be positive number")

        current_cash = db.execute("SELECT cash FROM users WHERE id = ?", user)[0][
            "cash"
        ]

        new_cash = add_cash + current_cash

        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user)

        flash(f"Added {add_cash}!")

        return redirect("/")

    else:
        return render_template("add.html")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":
        user = session["user_id"]

        if not request.form.get("username"):
            return apology("must provide username")

        elif not request.form.get("password"):
            return apology("must provide password")

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if rows[0]["id"] != user or len(rows) != 1:
            return apology("invalid username")

        elif not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid password")

        if not request.form.get("newpassword1") or not request.form.get("newpassword2"):
            return apology("must provide new password")

        newpassword1 = request.form.get("newpassword1")
        newpassword2 = request.form.get("newpassword2")

        if newpassword1 != newpassword2:
            return apology("new passwords must match")

        elif not is_safe_password(newpassword1):
            return apology(
                "new password must contain at least 8 characters, letters and digits"
            )

        else:
            hashed_pw = generate_password_hash(newpassword1)

            db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed_pw, user)

        session.clear()

        return redirect("/")

    else:
        return render_template("change.html")
