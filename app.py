from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session
)

from db import get_db_connection

from config import (
    SECRET_KEY, MAIL_SERVER, MAIL_PORT,
    MAIL_USERNAME, MAIL_PASSWORD, MAIL_SENDER
)

from werkzeug.security import generate_password_hash, check_password_hash

from datetime import datetime, timedelta

import secrets
import hashlib
import smtplib

from email.message import EmailMessage


app = Flask(__name__)
app.secret_key = SECRET_KEY



# ================= ACTIVE USER AND ADMIN SESSION SECURITY =================

@app.before_request
def check_active_user_session():

    # Skip static files
    if request.endpoint == "static":
        return None

    public_endpoints = {
        "home",
        "login",
        "logout",
        "register",
        "verify_email",
        "admin_login",
        "admin_logout"
    }

    # Check student or professor session
    user_id = session.get("user_id")

    if user_id:

        connection = get_db_connection()

        if not connection:
            return "Database temporarily unavailable. Please try again.", 503

        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT is_active, email_verified
                FROM users
                WHERE user_id = %s
            """, (user_id,))

            user = cursor.fetchone()

        finally:
            cursor.close()
            connection.close()

        if (
            not user
            or not user["is_active"]
            or not user["email_verified"]
        ):
            session.clear()

            flash(
                "Your account is inactive or not verified. Please contact library administration.",
                "error"
            )

            if request.endpoint in public_endpoints:
                return None

            return redirect(url_for("login"))

    # Check admin session
    admin_id = session.get("admin_id")

    if admin_id:

        connection = get_db_connection()

        if not connection:
            return "Database temporarily unavailable. Please try again.", 503

        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT is_active
                FROM admins
                WHERE admin_id = %s
            """, (admin_id,))

            admin = cursor.fetchone()

        finally:
            cursor.close()
            connection.close()

        if not admin or not admin["is_active"]:

            session.clear()

            flash(
                "Your admin account is inactive. Please contact the system administrator.",
                "error"
            )

            if request.endpoint in public_endpoints:
                return None

            return redirect(url_for("admin_login"))

    return None

# ================= END ACTIVE USER AND ADMIN SESSION SECURITY =================



# Send college email verification link
def send_verification_email(email, token):
    
    verification_link = url_for(
        "verify_email",
        token=token,
        _external=True
    )

    message = EmailMessage()
    message["Subject"] = "College Library Account Verification"
    message["From"] = MAIL_SENDER
    message["To"] = email

    message.set_content(
        f"""
        Welcome to the College Library Management System.

        Please click the link below to verify your email:

        {verification_link}

        This link will expire in 30 minutes.
        """
    )

    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(message)


# Homepage
@app.route("/")
def home():
    return render_template("index.html")


# User registration
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        roll_no = request.form.get("roll_no", "").strip()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        role = request.form.get("role", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # College email validation
        if not email.endswith("@mitsgwl.ac.in"):
            flash("Only college email addresses are allowed.")
            return redirect(url_for("register"))

        if not all([roll_no, name, email, password, confirm_password]):
            flash("Please fill in all required fields.")
            return redirect(url_for("register"))

        if role not in ["student", "professor"]:
            flash("Invalid account type.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        connection = get_db_connection()

        if not connection:
            flash("Database connection failed.")
            return redirect(url_for("register"))

        cursor = connection.cursor()

        try:
            cursor.execute(
                """
                SELECT user_id FROM users
                WHERE roll_no = %s OR email = %s
                """,
                (roll_no, email)
            )

            if cursor.fetchone():
                flash("Roll number or email is already registered.")
                return redirect(url_for("register"))

            password_hash = generate_password_hash(password)

            cursor.execute(
                """
                INSERT INTO users
                (roll_no, name, email, phone, role, password_hash)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (roll_no, name, email, phone, role, password_hash)
            )

            user_id = cursor.lastrowid

            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            expiry = datetime.now() + timedelta(minutes=30)

            cursor.execute(
                """
                INSERT INTO email_verification
                (user_id, token_hash, expires_at)
                VALUES (%s, %s, %s)
                """,
                (user_id, token_hash, expiry)
            )

            connection.commit()

            send_verification_email(email, token)

            flash("Registration successful! Check your college email.")
            return redirect(url_for("register"))

        except Exception as error:
            connection.rollback()
            print("Registration error:", error)
            flash("Registration could not be completed. Please try again.")

        finally:
            cursor.close()
            connection.close()

    return render_template("register.html")


# Verify college email
@app.route("/verify-email/<token>")
def verify_email(token):

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT user_id
            FROM email_verification
            WHERE token_hash = %s AND expires_at > NOW()
            """,
            (token_hash,)
        )

        result = cursor.fetchone()

        if not result:
            return "Verification link is invalid or expired."

        user_id = result[0]

        cursor.execute(
            "UPDATE users SET email_verified = TRUE WHERE user_id = %s",
            (user_id,)
        )

        cursor.execute(
            "DELETE FROM email_verification WHERE user_id = %s",
            (user_id,)
        )

        connection.commit()

        return "Your college email has been verified successfully!"

    except Exception as error:
        connection.rollback()
        print("Verification error:", error)
        return "Email verification failed."

    finally:
        cursor.close()
        connection.close()


# User login
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_db_connection()

        if not connection:
            flash("Database connection failed.")
            return redirect(url_for("login"))

        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute(
                """
                SELECT * FROM users
                WHERE email = %s AND is_active = TRUE
                """,
                (email,)
            )

            user = cursor.fetchone()

            if user and user["password_hash"] and check_password_hash(
                user["password_hash"], password
            ):

                if not user["email_verified"]:
                    flash("Please verify your college email first.")
                    return redirect(url_for("login"))

                session["user_id"] = user["user_id"]
                session["user_name"] = user["name"]
                session["user_role"] = user["role"]

                return redirect(url_for("dashboard"))

            flash("Invalid email or password.")

        except Exception as error:
            print("Login error:", error)
            flash("Login failed. Please try again.")

        finally:
            cursor.close()
            connection.close()

    return render_template("login.html")



# User dashboard
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:
        user_id = session["user_id"]

        # Total available book copies
        cursor.execute("""
            SELECT COALESCE(SUM(available_quantity), 0) AS available_books
            FROM books
        """)
        available_books = cursor.fetchone()["available_books"]

        # Currently issued books for this user
        cursor.execute("""
            SELECT COUNT(*) AS issued_books
            FROM issue_return
            WHERE user_id = %s
            AND status = 'issued'
        """, (user_id,))
        issued_books = cursor.fetchone()["issued_books"]

        # Overdue books for this user
        cursor.execute("""
            SELECT COUNT(*) AS overdue_books
            FROM issue_return
            WHERE user_id = %s
            AND status = 'issued'
            AND due_date < CURRENT_DATE
        """, (user_id,))
        overdue_books = cursor.fetchone()["overdue_books"]

        return render_template(
            "dashboard.html",
            available_books=available_books,
            issued_books=issued_books,
            overdue_books=overdue_books
        )

    except Exception as error:
        print("Student Dashboard Error:", error)
        return "Unable to load dashboard statistics."

    finally:
        cursor.close()
        connection.close()

# User logout
@app.route("/logout")
def logout():

    session.clear()
    flash("You have logged out successfully.")

    return redirect(url_for("login"))



# View and search available books
@app.route("/books")
def books():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:
        search = request.args.get("search", "").strip()

        cursor.execute(
            """
            SELECT book_id, title, author, category, available_quantity
            FROM books
            WHERE title LIKE %s
               OR author LIKE %s
               OR category LIKE %s
            ORDER BY title
            """,
            (
                f"%{search}%",
                f"%{search}%",
                f"%{search}%"
            )
        )

        books_list = cursor.fetchall()

        return render_template(
            "books.html",
            books=books_list,
            search=search
        )

    finally:
        cursor.close()
        connection.close()


# View only the logged-in user's library records
@app.route("/my-books")
def my_books():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT
                b.title,
                ir.issue_date,
                ir.due_date,
                ir.return_date,
                ir.status
            FROM issue_return ir
            JOIN books b ON ir.book_id = b.book_id
            WHERE ir.user_id = %s
            ORDER BY ir.issue_date DESC
            """,
            (session["user_id"],)
        )

        records = cursor.fetchall()

        return render_template(
            "my_books.html",
            records=records
        )

    finally:
        cursor.close()
        connection.close()


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        connection = get_db_connection()
        if not connection:
            flash("Database connection failed.", "error")
            return redirect(url_for("change_password"))

        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute(
                "SELECT password_hash FROM users WHERE user_id = %s",
                (session["user_id"],)
            )
            user = cursor.fetchone()

            if not user or not check_password_hash(
                user["password_hash"], current_password
            ):
                flash("Current password is incorrect.", "error")

            elif len(new_password) < 8:
                flash("New password must be at least 8 characters.", "error")

            elif new_password != confirm_password:
                flash("New passwords do not match.", "error")

            else:
                new_hash = generate_password_hash(new_password)

                cursor.execute(
                    "UPDATE users SET password_hash = %s WHERE user_id = %s",
                    (new_hash, session["user_id"])
                )
                connection.commit()

                flash("Password changed successfully!", "success")
                return redirect(url_for("dashboard"))

        except Exception as error:
            connection.rollback()
            print("Password change error:", error)
            flash("Something went wrong.", "error")

        finally:
            cursor.close()
            connection.close()

    return render_template("change_password.html")


@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT roll_no, name, email, phone, role
            FROM users
            WHERE user_id = %s
        """, (session["user_id"],))

        user = cursor.fetchone()

        if not user:
            return "User not found."

        return render_template("profile.html", user=user)

    finally:
        cursor.close()
        connection.close()


# ================= ADMIN LOGIN =================

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():

    if "admin_id" in session:
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_db_connection()

        if not connection:
            flash("Database connection failed.", "error")
            return redirect(url_for("admin_login"))

        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT admin_id, name, email, password_hash
                FROM admins
                WHERE email = %s AND is_active = TRUE
            """, (email,))

            admin = cursor.fetchone()

            if admin and check_password_hash(
                admin["password_hash"], password
            ):
                session.clear()
                session["admin_id"] = admin["admin_id"]
                session["admin_name"] = admin["name"]

                flash("Admin login successful!", "success")
                return redirect(url_for("admin_dashboard"))

            flash("Invalid admin email or password.", "error")

        finally:
            cursor.close()
            connection.close()

    return render_template("admin_login.html")



# ================= ADMIN DASHBOARD =================

@app.route("/admin-dashboard")
def admin_dashboard():

    if "admin_id" not in session:
        flash("Please login as admin first.", "error")
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:

        # Total book copies
        cursor.execute("""
            SELECT COALESCE(SUM(quantity), 0) AS total_books
            FROM books
        """)
        total_books = cursor.fetchone()["total_books"]

        # Total registered members
        cursor.execute("""
            SELECT COUNT(*) AS total_members
            FROM users
        """)
        total_members = cursor.fetchone()["total_members"]

        # Currently issued books
        cursor.execute("""
            SELECT COUNT(*) AS issued_books
            FROM issue_return
            WHERE status = 'issued'
        """)
        issued_books = cursor.fetchone()["issued_books"]

        # Returned books
        cursor.execute("""
            SELECT COUNT(*) AS returned_books
            FROM issue_return
            WHERE status = 'returned'
        """)
        returned_books = cursor.fetchone()["returned_books"]

        # Overdue books
        cursor.execute("""
            SELECT COUNT(*) AS overdue_books
            FROM issue_return
            WHERE status = 'issued'
            AND due_date < CURRENT_DATE
        """)
        overdue_books = cursor.fetchone()["overdue_books"]

        return render_template(
            "admin_dashboard.html",
            total_books=total_books,
            total_members=total_members,
            issued_books=issued_books,
            returned_books=returned_books,
            overdue_books=overdue_books
        )

    except Exception as error:

        print("Admin Dashboard Error:", error)

        flash("Unable to load dashboard statistics.", "error")

        return redirect(url_for("admin_dashboard"))

    finally:
        cursor.close()
        connection.close()

# ================= END ADMIN DASHBOARD =================



# ================= ADMIN LOGOUT =================

@app.route("/admin-logout")
def admin_logout():

    session.pop("admin_id", None)
    session.pop("admin_name", None)

    flash("Admin logged out successfully.", "success")

    return redirect(url_for("admin_login"))


# ================= MANAGE BOOKS =================

@app.route("/manage-books", methods=["GET", "POST"])
def manage_books():

    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:
        if request.method == "POST":

            title = request.form.get("title", "").strip()
            author = request.form.get("author", "").strip()
            category = request.form.get("category", "").strip()
            quantity = request.form.get("quantity", type=int)

            if not title or not author or not quantity or quantity < 1:
                flash("Please enter valid book details.", "error")
            else:
                cursor.execute("""
                    INSERT INTO books
                    (title, author, category, quantity, available_quantity)
                    VALUES (%s, %s, %s, %s, %s)
                """, (title, author, category, quantity, quantity))

                connection.commit()
                flash("Book added successfully!", "success")

            return redirect(url_for("manage_books"))

        cursor.execute("SELECT * FROM books ORDER BY book_id DESC")
        books = cursor.fetchall()

        return render_template("manage_books.html", books=books)

    finally:
        cursor.close()
        connection.close()



# ================= MANAGE MEMBERS =================

@app.route("/manage-members")
def manage_members():

    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT user_id, roll_no, name, email, phone, role, is_active
            FROM users
            ORDER BY user_id DESC
        """)

        members = cursor.fetchall()

        return render_template(
            "manage_members.html",
            members=members
        )

    finally:
        cursor.close()
        connection.close()


# ================= ACTIVATE / DEACTIVATE MEMBER =================

@app.route("/toggle-member/<int:user_id>", methods=["POST"])
def toggle_member(user_id):

    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    if not connection:
        flash("Database connection failed.", "error")
        return redirect(url_for("manage_members"))

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT user_id, is_active
            FROM users
            WHERE user_id = %s
        """, (user_id,))

        member = cursor.fetchone()

        if not member:
            flash("Member not found.", "error")
            return redirect(url_for("manage_members"))

        new_status = not bool(member["is_active"])

        cursor.execute("""
            UPDATE users
            SET is_active = %s
            WHERE user_id = %s
        """, (new_status, user_id))

        connection.commit()

        if new_status:
            flash("Member activated successfully!", "success")
        else:
            flash("Member deactivated successfully!", "success")

        return redirect(url_for("manage_members"))

    except Exception as error:
        connection.rollback()
        print("Member Status Error:", error)
        flash("Unable to update member status.", "error")
        return redirect(url_for("manage_members"))

    finally:
        cursor.close()
        connection.close()


# ================= END MEMBER MANAGEMENT =================

# ================= EDIT BOOK =================

@app.route("/edit-book/<int:book_id>", methods=["GET", "POST"])
def edit_book(book_id):

    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT * FROM books WHERE book_id = %s",
            (book_id,)
        )
        book = cursor.fetchone()

        if not book:
            flash("Book not found.", "error")
            return redirect(url_for("manage_books"))

        if request.method == "POST":

            title = request.form.get("title", "").strip()
            author = request.form.get("author", "").strip()
            category = request.form.get("category", "").strip()
            quantity = request.form.get("quantity", type=int)

            if not title or not author or not quantity or quantity < 1:
                flash("Please enter valid book details.", "error")
                return render_template("edit_book.html", book=book)

            cursor.execute("""
                SELECT COUNT(*) AS issued_count
                FROM issue_return
                WHERE book_id = %s AND status = 'issued'
            """, (book_id,))

            issued_count = cursor.fetchone()["issued_count"]

            if quantity < issued_count:
                flash(
                    "Total quantity cannot be less than currently issued books.",
                    "error"
                )
                return render_template("edit_book.html", book=book)

            available_quantity = quantity - issued_count

            cursor.execute("""
                UPDATE books
                SET title = %s,
                    author = %s,
                    category = %s,
                    quantity = %s,
                    available_quantity = %s
                WHERE book_id = %s
            """, (
                title, author, category,
                quantity, available_quantity, book_id
            ))

            connection.commit()

            flash("Book updated successfully!", "success")
            return redirect(url_for("manage_books"))

        return render_template("edit_book.html", book=book)

    finally:
        cursor.close()
        connection.close()


# ================= DELETE BOOK =================

@app.route("/delete-book/<int:book_id>", methods=["POST"])
def delete_book(book_id):

    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT book_id FROM books WHERE book_id = %s",
            (book_id,)
        )

        book = cursor.fetchone()

        if not book:
            flash("Book not found.", "error")
            return redirect(url_for("manage_books"))

        cursor.execute("""
            SELECT COUNT(*) AS issue_count
            FROM issue_return
            WHERE book_id = %s
        """, (book_id,))

        issue_count = cursor.fetchone()["issue_count"]

        if issue_count > 0:
            flash(
                "This book has issue history and cannot be deleted.",
                "error"
            )
        else:
            cursor.execute(
                "DELETE FROM books WHERE book_id = %s",
                (book_id,)
            )
            connection.commit()
            flash("Book deleted successfully!", "success")

        return redirect(url_for("manage_books"))

    finally:
        cursor.close()
        connection.close()



# ================= ISSUE BOOK =================

@app.route("/issue-book", methods=["GET", "POST"])
def issue_book():

    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:
        if request.method == "POST":

            user_id = request.form.get("user_id", type=int)
            book_id = request.form.get("book_id", type=int)
            issue_date = request.form.get("issue_date")
            due_date = request.form.get("due_date")

            # Check required fields
            if not user_id or not book_id or not issue_date or not due_date:
                flash("Please fill in all fields.", "error")
                return redirect(url_for("issue_book"))

            # Validate dates
            from datetime import date

            try:
                issue_date = date.fromisoformat(issue_date)
                due_date = date.fromisoformat(due_date)

            except ValueError:
                flash("Invalid date.", "error")
                return redirect(url_for("issue_book"))

            if due_date <= issue_date:
                flash("Due date must be after issue date.", "error")
                return redirect(url_for("issue_book"))

            # Check active and verified member
            cursor.execute("""
                SELECT user_id
                FROM users
                WHERE user_id = %s
                AND email_verified = TRUE
                AND is_active = TRUE
                FOR UPDATE
            """, (user_id,))

            member = cursor.fetchone()

            if not member:
                flash("Member is not active or verified.", "error")
                return redirect(url_for("issue_book"))

            # Check borrowing limit of 5 books
            cursor.execute("""
                SELECT COUNT(*) AS active_loans
                FROM issue_return
                WHERE user_id = %s
                AND status = 'issued'
            """, (user_id,))

            loan_count = cursor.fetchone()["active_loans"]

            if loan_count >= 5:
                flash(
                    "This member has already reached the borrowing limit of 5 books.",
                    "error"
                )
                return redirect(url_for("issue_book"))

            # Check book availability
            cursor.execute("""
                SELECT book_id, available_quantity
                FROM books
                WHERE book_id = %s
                FOR UPDATE
            """, (book_id,))

            book = cursor.fetchone()

            if not book or book["available_quantity"] <= 0:
                flash("This book is not available.", "error")
                return redirect(url_for("issue_book"))

            # Insert issue record
            cursor.execute("""
                INSERT INTO issue_return
                (book_id, user_id, issue_date, due_date, status)
                VALUES (%s, %s, %s, %s, 'issued')
            """, (book_id, user_id, issue_date, due_date))

            # Reduce available book quantity
            cursor.execute("""
                UPDATE books
                SET available_quantity = available_quantity - 1
                WHERE book_id = %s
            """, (book_id,))

            connection.commit()

            flash("Book issued successfully!", "success")
            return redirect(url_for("issue_book"))

        # Load active and verified members
        cursor.execute("""
            SELECT user_id, roll_no, name, role
            FROM users
            WHERE email_verified = TRUE
            AND is_active = TRUE
            ORDER BY name
        """)

        members = cursor.fetchall()

        # Load available books
        cursor.execute("""
            SELECT book_id, title, available_quantity
            FROM books
            WHERE available_quantity > 0
            ORDER BY title
        """)

        books = cursor.fetchall()

        return render_template(
            "issue_book.html",
            members=members,
            books=books
        )

    except Exception as error:
        connection.rollback()
        print("Issue Book Error:", error)

        flash(
            "Unable to issue book. Please check the details.",
            "error"
        )

        return redirect(url_for("issue_book"))

    finally:
        cursor.close()
        connection.close()

# ================= END ISSUE BOOK =================


# ================= RETURN BOOK =================

@app.route("/return-book", methods=["GET", "POST"])
def return_book():

    # Check admin login
    if "admin_id" not in session:
        flash("Please login as admin first.", "error")
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:

        # ================= PROCESS BOOK RETURN =================

        if request.method == "POST":

            issue_id = request.form.get("issue_id", type=int)

            if not issue_id:
                flash("Invalid return request.", "error")
                return redirect(url_for("return_book"))

            cursor.execute("""
                SELECT issue_id, book_id
                FROM issue_return
                WHERE issue_id = %s
                AND status = 'issued'
                FOR UPDATE
            """, (issue_id,))

            issued_book = cursor.fetchone()

            if not issued_book:
                flash("Book already returned or record not found.", "error")
                return redirect(url_for("return_book"))

            # Increase available book quantity
            cursor.execute("""
                UPDATE books
                SET available_quantity = available_quantity + 1
                WHERE book_id = %s
                AND available_quantity < quantity
            """, (issued_book["book_id"],))

            if cursor.rowcount != 1:
                connection.rollback()
                flash("Unable to update book availability.", "error")
                return redirect(url_for("return_book"))

            # Update issue record
            cursor.execute("""
                UPDATE issue_return
                SET status = 'returned',
                    return_date = CURRENT_DATE
                WHERE issue_id = %s
                AND status = 'issued'
            """, (issue_id,))

            connection.commit()

            flash("Book returned successfully!", "success")

            return redirect(url_for("return_book"))

        # ================= DISPLAY ISSUED BOOKS =================

        cursor.execute("""
            SELECT
                ir.issue_id,
                ir.issue_date,
                ir.due_date,
                b.title,
                u.name,
                u.roll_no
            FROM issue_return ir

            JOIN books b
                ON ir.book_id = b.book_id

            JOIN users u
                ON ir.user_id = u.user_id

            WHERE ir.status = 'issued'

            ORDER BY ir.due_date ASC
        """)

        issued_books = cursor.fetchall()

        return render_template(
            "return_book.html",
            issued_books=issued_books
        )

    except Exception as error:

        connection.rollback()

        print("Return Book Error:", error)

        flash(
            "Unable to process book return. Please check the terminal.",
            "error"
        )

        return redirect(url_for("return_book"))

    finally:

        cursor.close()
        connection.close()


# ================= END RETURN BOOK =================


# ================= BOOK DETAILS =================

@app.route("/book-details/<int:book_id>")
def book_details(book_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT book_id, title, author, category,
                   quantity, available_quantity
            FROM books
            WHERE book_id = %s
        """, (book_id,))

        book = cursor.fetchone()

        if not book:
            flash("Book not found.", "error")
            return redirect(url_for("books"))

        return render_template(
            "book_details.html",
            book=book
        )

    finally:
        cursor.close()
        connection.close()

# ================= END BOOK DETAILS =================


# ================= OVERDUE BOOKS =================

@app.route("/overdue-books")
def overdue_books():

    if "admin_id" not in session:
        flash("Please login as admin first.", "error")
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                ir.issue_id,
                b.title,
                u.name,
                u.roll_no,
                ir.issue_date,
                ir.due_date,
                DATEDIFF(CURRENT_DATE, ir.due_date) AS overdue_days
            FROM issue_return ir
            JOIN books b ON ir.book_id = b.book_id
            JOIN users u ON ir.user_id = u.user_id
            WHERE ir.status = 'issued'
              AND ir.due_date < CURRENT_DATE
            ORDER BY ir.due_date ASC
        """)

        overdue_list = cursor.fetchall()

        return render_template(
            "overdue_books.html",
            overdue_books=overdue_list
        )

    finally:
        cursor.close()
        connection.close()

# ================= END OVERDUE BOOKS =================


# ================= LIBRARY REPORTS =================

@app.route("/library-reports")
def library_reports():

    if "admin_id" not in session:
        flash("Please login as admin first.", "error")
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    if not connection:
        return "Database connection failed."

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                (SELECT COALESCE(SUM(quantity), 0)
                 FROM books) AS total_books,

                (SELECT COUNT(*)
                 FROM users) AS total_members,

                (SELECT COUNT(*)
                 FROM issue_return
                 WHERE status = 'issued') AS issued_books,

                (SELECT COUNT(*)
                 FROM issue_return
                 WHERE status = 'returned') AS returned_books,

                (SELECT COUNT(*)
                 FROM issue_return
                 WHERE status = 'issued'
                   AND due_date < CURRENT_DATE) AS overdue_books
        """)

        report = cursor.fetchone()

        return render_template(
            "library_reports.html",
            report=report
        )

    finally:
        cursor.close()
        connection.close()

# ================= END LIBRARY REPORTS =================


if __name__ == "__main__":
    app.run(debug=True)
