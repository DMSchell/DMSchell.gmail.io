import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///library.db")

@app.route("/")
@login_required
def posts():
    if request.method == "GET":
        posts = db.execute("SELECT image, description, likes, poster, id FROM posts")
        comments = db.execute("SELECT text, likes, poster, attachedTo, id FROM comments")
        return render_template ("posts.html", posts = posts, comments = comments)



@app.route("/user_search", methods=["GET", "POST"])
@login_required
def user_search():
    if request.method == "GET":
        return render_template ("user_search.html")



@app.route("/followed")
@login_required
def followed():
    # Time due
    return render_template ("followed.html")



@app.route("/return", methods=["GET", "POST"])
@login_required
def return_function():
    if request.method == "GET":
        return render_template ("return.html")

    else:
        if not request.form.get("image"):
            return render_template ("error.html", error = "Must provide image.")

        check = db.execute("SELECT id, likes, poster FROM posts WHERE image = ?", request.form.get("image"))

        if len(check) != 1:
            return render_template ("error.html", error = "You have not borrowed this book.")

        book_id = db.execute("SELECT id FROM posts WHERE image = ?", request.form.get("image"))
        db.execute("DELETE FROM borrowed WHERE book_id = ? AND user_id = ?", book_id[0]["id"], session.get("user_id"))
        db.execute("UPDATE posts SET likes = ? WHERE image = ?", int(check[0]["likes"]) + 1, request.form.get("image"))


        # Redirect user to home page
        return redirect("/")



@app.route("/results", methods=["POST"])
@login_required
def results():
    if not request.form.get("search"):
        return render_template ("error.html", error = "Must provide image or description.")
    else:
        # Might have issues with question mark
        posts = db.execute("SELECT image, description, likes, poster FROM posts WHERE image like '%' || ? || '%'  OR description like '%' || ? || '%'", request.form.get("search"), request.form.get("search"))
        return render_template ("posts.html", posts = posts)




# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template ("error.html", error = "Must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template ("error.html", error = "Must provide password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template ("error.html", error = "invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["user_name"] = rows[0]["username"]
        session["user_about"] = rows[0]["about"]
        session["user_profession"] = rows[0]["profession"]
        session["user_follows"] = rows[0]["follows"]

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

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    else:
        # Error Checking
        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("error.html", error = "Must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template ("error.html", error = "Must provide password")

        # Ensure password was submitted
        elif not request.form.get("confirmation"):
            return render_template ("error.html", error = "Must provide confirmation password")

        elif int(len(request.form.get("password"))) < 6:
            return render_template ("error.html", error = "Password must have at least six characters.")

        elif int(len(request.form.get("password"))) > 20:
            return render_template ("error.html", error = "Password must have less then 20 characters.")

        # Ensure about me was submitted
        elif not request.form.get("about"):
            return render_template ("error.html", error = "Must provide about me")

        # Query database for username
        query = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username doesn't exist
        if len(query) != 0:
            return render_template ("error.html", error = "This username has already been used")

        # Ensure password and confirmation match
        if request.form.get("confirmation") != request.form.get("password"):
            return render_template ("error.html", error = "Passwords don't match")

        # Storing username and hashed password into database
        username = request.form.get("username")
        about = request.form.get("about")
        profession = request.form.get("profession")
        password_hash = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash, about, profession) VALUES(?, ?, ?, ?)", username, password_hash, profession, about)

        # Redirect user to home page
        return redirect("/")


@app.route("/reset", methods=["GET", "POST"])
def reset():
    """Reset password"""
    if request.method == "GET":
        return render_template("reset.html")

    else:
        # Error Checking
        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template ("error.html", error = "Must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template ("error.html", error = "Must provide password")

        # Ensure password was submitted
        elif not request.form.get("confirmation"):
            return render_template ("error.html", error = "Must provide confirmation password")

        # Query database for username
        query = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username doesn't exist
        if len(query) != 1:
            return render_template ("error.html", error = "This is an invalid username. ")

        # Ensure password and confirmation match
        if request.form.get("confirmation") != request.form.get("password"):
            return render_template ("error.html", error = "Passwords don't match.")

        # Storing hashed password into database
        username = request.form.get("username")
        password_hash = generate_password_hash(request.form.get("password"))
        db.execute("UPDATE users SET hash = ? WHERE username = ?", password_hash, username)

        # Redirect user to home page
        return redirect("/")

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "GET":
        return render_template ("add.html")

    else:
        if not request.form.get("Subtext"):
            return render_template ("error.html", error = "Provide a subtext.")

        # check = db.execute("SELECT * FROM posts WHERE image = ?", request.form.get("Image Address"))

        db.execute("INSERT INTO posts (image, description, likes, poster) VALUES(?, ?, ?, ?)", request.form.get("Subtext"), request.form.get("Image Address"), 0, session["user_name"])

        # Redirect user to home page
        return redirect("/")

@app.route("/userpage", methods=["GET", "POST"])
@login_required
def userpage():
    """Look at the user's page"""
    if request.method == "GET":
        return render_template ("userpage.html")

@app.route("/goToUserpage", methods=["GET", "POST"])
def goToUserpage():
    """Look at another user's page"""
    rows = db.execute("SELECT * FROM users WHERE username = ?", request.args.get('name'))
    session["follow_id"] = rows[0]["id"]
    session["follow_name"] = rows[0]["username"]
    session["follow_about"] = rows[0]["about"]
    session["follow_profession"] = rows[0]["profession"]
    if request.method == "GET":
        return render_template ("goToUserpage.html")

def follow(nameToFollow):
    """follow another user"""
    session["user_follows"] = nameToFollow
    return render_template ("/")

def unfollow(nameToUnfollow):
    """unfollow a user"""
    #session["user_follows"] = NULL
    return render_template ("/")
