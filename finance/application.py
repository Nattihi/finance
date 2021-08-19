from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
from flask_session import Session
from tempfile import gettempdir, mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from flask.helpers import get_flashed_messages
from helpers import apology, login_required, lookup, usd




# configure application
app = Flask(__name__)

# ensure responses aren't cached
if app.config["DEBUG"]:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response

# custom filter
app.jinja_env.filters["usd"] = usd

# configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = gettempdir()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """show index portfolio"""
  
    # select each symbol, shares owned by the user
    stocks = db.execute("SELECT shares, symbol, price_share \
                         FROM portfolio WHERE id = :id", id=session["user_id"])
    
    # temporary variable
    total_cash = 0
    
    # get index varibales from portfolio
    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["total"] = stock["price"] * stock["shares"]
        total_cash += stock["total"]
        
    # update user's cash 
    updated_cash = db.execute("SELECT cash FROM users \
                               WHERE id=:id", id=session["user_id"])
    
    # update total cash -> cash + shares worth
    total_cash += updated_cash[0]["cash"]

    # generate index        
    return render_template("index.html", stocks=stocks, cash=usd(updated_cash[0]["cash"]), total=usd(total_cash))
                            

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock."""
    
    if request.method == "GET":
        return render_template("buy.html")
    else:
        # ensure proper symbol
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Invalid Symbol")
        
        # ensure positive shares
        try:
            shares = int(request.form.get("shares"))
            if shares <= 0:
                return apology("Shares must be positive integer")
        except:
            return apology("Shares must be positive integer")
        
        # select user's cash
        money = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        
        # check if user can buy or lack cash
        if not money or float(money[0]["cash"]) < stock["price"] * shares:
            return apology("Not enough money")
        
        # update history
        db.execute("INSERT INTO histories (symbol, shares, price, id) \
                    VALUES(:symbol, :shares, :price, :id)", symbol=stock["symbol"], shares=shares, 
                   price=usd(stock["price"]), id=session["user_id"])
                       
        # update user cash               
        db.execute("UPDATE users SET cash = cash - :purchase WHERE id = :id", 
                   id=session["user_id"], purchase=stock["price"] * float(shares))
                        
        # Select user shares of that symbol
        user_shares = db.execute("SELECT shares FROM portfolio \
                           WHERE id = :id AND symbol=:symbol", id=session["user_id"], symbol=stock["symbol"])
                           
        # if user doesn't has shares of that symbol, create new stock object
        if not user_shares:
            db.execute("INSERT INTO portfolio (name, shares, price_share, total, symbol, id) \
                        VALUES(:name, :shares, :price, :total, :symbol, :id)", name=stock["name"], 
                       shares=shares, price=usd(stock["price"]), total=usd(shares * stock["price"]), \
                        symbol=stock["symbol"], id=session["user_id"])
                        
        # Else increment the shares count
        else:
            shares_total = user_shares[0]["shares"] + shares
            db.execute("UPDATE portfolio SET shares=:shares \
                        WHERE id=:id AND symbol=:symbol", shares=+shares_total, id=session["user_id"], 
                       symbol=stock["symbol"])
        
        # return to index
        return redirect(url_for("index"))
        

@app.route("/history")
@login_required
def history():
    """Show history of portfolio."""
    # get users history
    histories = db.execute("SELECT * from histories WHERE id=:id", id=session["user_id"])
    
    return render_template("history.html", histories=histories)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST 
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        users = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(users) != 1 or not check_password_hash(
            users[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = users[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")
        

@app.route("/logout")
def logout():
    """Log user out."""

    # forget any user_id
    session.clear()

    # redirect user to login form
    return redirect(url_for("login"))
    

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    
    # get correct symbol from user
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        if quote == None:
            return apology("invalid symbol", 400)

        return render_template("quoted.html", quote=quote)

    # User reached route via GET
    else:
        return render_template("quote.html")
    

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        
        # get username, password, confirm
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure the username was submitted
        if not username:
            return apology("must provide username", 400)
        # Ensure the username doesn't exists
        elif len(rows) != 0:
            return apology("username already exists", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure confirmation password was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide a confirmation password", 400)

        # Ensure passwords match
        elif not password == confirmation:
            return apology("passwords must match", 400)

        else:
            # Generate the hash of the password
            hash = generate_password_hash(
                password, method="pbkdf2:sha256", salt_length=8
            )
            # Insert the new user
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?) ", username, hash,
            )
            # Redirect user to home page
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")          
 
        
@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock."""

    # generate portfolio
    if request.method == "GET":
        stocks = db.execute(
            "SELECT symbol, SUM(shares) as shares FROM portfolio WHERE id = :id GROUP BY symbol HAVING shares > 0", id=session["user_id"])

        return render_template("sell.html", stocks=stocks)
    else:
        # ensure proper symbol
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Invalid Symbol")
        
        # ensure proper number of shares
        try:
            shares = int(request.form.get("shares"))
            if shares <= 0:
                return apology("Shares must be positive integer")
        except:
            return apology("Shares must be positive integer")
        
        # Check if we have enough shares
        sell_shares = db.execute("SELECT SUM(shares) as shares FROM portfolio WHERE id = :id AND symbol = :symbol GROUP BY symbol",
                                  id=session["user_id"], symbol=request.form.get("symbol"))
        
        if len(sell_shares) != 1 or sell_shares[0]["shares"] <= 0 or sell_shares[0]["shares"] < shares:
            return apology("you can't sell less than 0 or more than you own", 400)
        
        price = stock["price"]

        # Calculate the price of requested shares
        total_value = price * shares

        # update history
        db.execute("INSERT INTO histories (symbol, shares, price, id) \
                    VALUES(:symbol, :shares, :price, :id)", symbol=stock["symbol"], shares=-shares, 
                   price=usd(stock["price"]), id=session["user_id"])
                       
        # update user cash               
        db.execute("UPDATE users SET cash = cash + :sell WHERE id = :id", 
                    id=session["user_id"], sell=+stock["price"] * float(shares))
                        
        # Select user shares of that symbol
        user_shares = db.execute("SELECT shares FROM portfolio \
                           WHERE id = :id AND symbol=:symbol", id=session["user_id"], symbol=stock["symbol"])
                           
        shares_total = user_shares[0]["shares"] - shares
        
        if shares_total == 0:
            db.execute("DELETE FROM portfolio WHERE id=:id AND symbol=:symbol", 
                       id=session["user_id"], symbol=request.form.get("symbol"))
            
        else:
            db.execute("UPDATE portfolio SET shares=:shares \
                       WHERE id=:id AND symbol=:symbol", shares=shares_total, id=session["user_id"], 
                       symbol=stock["symbol"])
        
        # return to index
        return redirect(url_for("index"))

        
@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    """ deposit cash """
    # get amount of deposited cash
    if request.method == "POST":

        deposit_amount = request.form.get("amount")
        current = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])

        print(current)
        
        # cant deposit negative cash
        if int(deposit_amount) <= 0:
            return apology("You need to enter a positive number")

        # update cash open to user
        db.execute("UPDATE users SET cash = :new_val WHERE id = :user_id", 
                   new_val=current[0]["cash"]+int(deposit_amount), user_id=session["user_id"])

        return redirect("/")
    else:
        return render_template("deposit.html")
        
        
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow user to change her password"""

    if request.method == "POST":

        # Ensure current password is not empty
        if not request.form.get("current_password"):
            return apology("must provide current password", 400)

        # Query database for user_id
        rows = db.execute("SELECT hash FROM users WHERE id = :user_id", user_id=session["user_id"])

        # Ensure current password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("current_password")):
            return apology("invalid password", 400)

        # Ensure new password is not empty
        if not request.form.get("new_password"):
            return apology("must provide new password", 400)

        # Ensure confirmation is not empty
        elif not request.form.get("new_password_confirmation"):
            return apology("must provide new password confirmation", 400)

        # Ensure match
        elif request.form.get("new_password") != request.form.get("new_password_confirmation"):
            return apology("new password and confirmation must match", 400)

        # Update database
        hash = generate_password_hash(request.form.get("new_password"))
        rows = db.execute("UPDATE users SET hash = :hash WHERE id = :user_id", user_id=session["user_id"], hash=hash)

        # Show flash
        flash("Changed!")

    return render_template("change_password.html")
  
    
@app.route("/loan", methods=["GET", "POST"])
@login_required
def loan():
    """Get a loan."""
    
    if request.method == "POST":
        
        # ensure must be integers
        try:
            loan = int(request.form.get("loan"))
            if loan < 0:
                return apology("Loan can´t be negative")
            elif loan > 1000:
                return apology("Cannot loan more than $1000")
        except:
            return apology("Can´t loan negative amount")
            
        # update user cash              
        db.execute("UPDATE users SET cash = cash + :loan WHERE id = :id", loan=loan, id=session["user_id"])
        
        # return to index
        return apology("Loan is successful")
    
    else:
        return render_template("loan.html")