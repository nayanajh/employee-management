from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# Secret key for sessions
app.secret_key = "employee-management-secret-key"

DATABASE = "database.db"


# -----------------------------------
# DATABASE CONNECTION
# -----------------------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# -----------------------------------
# CREATE DATABASE TABLES
# -----------------------------------

def init_db():
    conn = get_db()

    # Admin table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Employee table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            department TEXT NOT NULL,
            designation TEXT NOT NULL,
            salary REAL NOT NULL,
            date_of_joining TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# -----------------------------------
# LOGIN REQUIRED DECORATOR
# -----------------------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "admin_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


# -----------------------------------
# HOME
# -----------------------------------

@app.route("/")
def home():

    if "admin_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# -----------------------------------
# REGISTER
# -----------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Validation
        if not name or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must contain at least 6 characters.", "error")
            return render_template("register.html")

        try:

            conn = get_db()

            hashed_password = generate_password_hash(password)

            conn.execute("""
                INSERT INTO admins (name, email, password)
                VALUES (?, ?, ?)
            """, (name, email, hashed_password))

            conn.commit()
            conn.close()

            flash("Registration successful. Please login.", "success")

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:

            flash("Email already registered.", "error")

    return render_template("register.html")


# -----------------------------------
# LOGIN
# -----------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db()

        admin = conn.execute("""
            SELECT * FROM admins
            WHERE email = ?
        """, (email,)).fetchone()

        conn.close()

        if admin and check_password_hash(admin["password"], password):

            session["admin_id"] = admin["id"]
            session["admin_name"] = admin["name"]

            flash("Login successful!", "success")

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


# -----------------------------------
# LOGOUT
# -----------------------------------

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# -----------------------------------
# DASHBOARD
# -----------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()

    total_employees = conn.execute("""
        SELECT COUNT(*) FROM employees
    """).fetchone()[0]

    departments = conn.execute("""
        SELECT department, COUNT(*) as count
        FROM employees
        GROUP BY department
    """).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total_employees=total_employees,
        departments=departments
    )


# -----------------------------------
# VIEW EMPLOYEES
# -----------------------------------

@app.route("/employees")
@login_required
def employees():

    search = request.args.get("search", "").strip()

    conn = get_db()

    if search:

        employee_list = conn.execute("""
            SELECT * FROM employees
            WHERE name LIKE ?
            OR email LIKE ?
            OR department LIKE ?
            OR designation LIKE ?
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        )).fetchall()

    else:

        employee_list = conn.execute("""
            SELECT * FROM employees
            ORDER BY id DESC
        """).fetchall()

    conn.close()

    return render_template(
        "employees.html",
        employees=employee_list,
        search=search
    )


# -----------------------------------
# ADD EMPLOYEE
# -----------------------------------

@app.route("/employees/add", methods=["GET", "POST"])
@login_required
def add_employee():

    if request.method == "POST":

        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        phone = request.form["phone"].strip()
        department = request.form["department"].strip()
        designation = request.form["designation"].strip()
        salary = request.form["salary"].strip()
        date_of_joining = request.form["date_of_joining"]

        # Validation
        if not all([
            name,
            email,
            phone,
            department,
            designation,
            salary,
            date_of_joining
        ]):
            flash("All fields are required.", "error")
            return render_template("add_employee.html")

        if not phone.isdigit() or len(phone) != 10:
            flash("Phone number must contain exactly 10 digits.", "error")
            return render_template("add_employee.html")

        try:
            salary_value = float(salary)

            if salary_value <= 0:
                flash("Salary must be greater than zero.", "error")
                return render_template("add_employee.html")

        except ValueError:

            flash("Please enter a valid salary.", "error")
            return render_template("add_employee.html")

        try:

            conn = get_db()

            conn.execute("""
                INSERT INTO employees
                (name, email, phone, department, designation, salary, date_of_joining)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                name,
                email,
                phone,
                department,
                designation,
                salary_value,
                date_of_joining
            ))

            conn.commit()
            conn.close()

            flash("Employee added successfully!", "success")

            return redirect(url_for("employees"))

        except sqlite3.IntegrityError:

            flash("An employee with this email already exists.", "error")

    return render_template("add_employee.html")


# -----------------------------------
# EDIT EMPLOYEE
# -----------------------------------

@app.route("/employees/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_employee(id):

    conn = get_db()

    employee = conn.execute("""
        SELECT * FROM employees
        WHERE id = ?
    """, (id,)).fetchone()

    if not employee:

        conn.close()

        flash("Employee not found.", "error")

        return redirect(url_for("employees"))

    if request.method == "POST":

        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        phone = request.form["phone"].strip()
        department = request.form["department"].strip()
        designation = request.form["designation"].strip()
        salary = request.form["salary"].strip()
        date_of_joining = request.form["date_of_joining"]

        if not all([
            name,
            email,
            phone,
            department,
            designation,
            salary,
            date_of_joining
        ]):

            flash("All fields are required.", "error")

            conn.close()

            return render_template(
                "edit_employee.html",
                employee=employee
            )

        if not phone.isdigit() or len(phone) != 10:

            flash("Phone number must contain exactly 10 digits.", "error")

            conn.close()

            return render_template(
                "edit_employee.html",
                employee=employee
            )

        try:

            salary_value = float(salary)

            if salary_value <= 0:
                raise ValueError

        except ValueError:

            flash("Please enter a valid salary.", "error")

            conn.close()

            return render_template(
                "edit_employee.html",
                employee=employee
            )

        try:

            conn.execute("""
                UPDATE employees
                SET name = ?,
                    email = ?,
                    phone = ?,
                    department = ?,
                    designation = ?,
                    salary = ?,
                    date_of_joining = ?
                WHERE id = ?
            """, (
                name,
                email,
                phone,
                department,
                designation,
                salary_value,
                date_of_joining,
                id
            ))

            conn.commit()

            conn.close()

            flash("Employee updated successfully!", "success")

            return redirect(url_for("employees"))

        except sqlite3.IntegrityError:

            conn.close()

            flash("Another employee already uses this email.", "error")

    conn.close()

    return render_template(
        "edit_employee.html",
        employee=employee
    )


# -----------------------------------
# DELETE EMPLOYEE
# -----------------------------------

@app.route("/employees/delete/<int:id>", methods=["POST"])
@login_required
def delete_employee(id):

    conn = get_db()

    conn.execute("""
        DELETE FROM employees
        WHERE id = ?
    """, (id,))

    conn.commit()
    conn.close()

    flash("Employee deleted successfully!", "success")

    return redirect(url_for("employees"))


# -----------------------------------
# RUN APPLICATION
# -----------------------------------

if __name__ == "__main__":

    init_db()

    app.run(debug=True)