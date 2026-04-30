from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
import bcrypt
import pyotp
import qrcode
from flask_jwt_extended import JWTManager, create_access_token, decode_token

app = Flask(__name__)
app.secret_key = "secret123"
app.config["JWT_SECRET_KEY"] = "jwt-secret"

jwt = JWTManager(app)

# ================= DB =================

def connect_db():
    return sqlite3.connect("database.db")

def init_db():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT,
            email    TEXT UNIQUE,
            password BLOB,
            role     TEXT,
            secret   TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ================= HELPER =================

def is_logged_in():
    """تحقق إن اليوزر عامل login وعنده توكن صالح"""
    return "user_id" in session and "token" in session

def require_login():
    """لو مش logged in → redirect للـ login"""
    if not is_logged_in():
        return redirect("/login")
    return None

def require_role(role):
    """تحقق من الـ role"""
    err = require_login()
    if err:
        return err
    if session.get("role") != role:
        return "Unauthorized - You don't have permission to access this page", 403
    return None

# ================= HOME =================

@app.route("/")
def home():
    return redirect("/login")

# ================= REGISTER =================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name     = request.form.get("name")
        email    = request.form.get("email")
        password = request.form.get("password")
        role     = request.form.get("role")

        if not all([name, email, password, role]):
            return render_template("register.html", error="All fields are required")

        # تحقق إن الإيميل مش موجود قبل كده
        conn = connect_db()
        cur  = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        if cur.fetchone():
            conn.close()
            return render_template("register.html", error="Email already registered")

        # 🔐 Hash password
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # 🔑 2FA secret
        secret = pyotp.random_base32()

        # 📷 QR code
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=email, issuer_name="SecureApp"
        )
        img        = qrcode.make(uri)
        safe_email = email.replace("@", "_").replace(".", "_")
        img.save(f"static/qrcode_{safe_email}.png")

        # 🗄️ DB insert
        cur.execute(
            "INSERT INTO users(name, email, password, role, secret) VALUES (?,?,?,?,?)",
            (name, email, hashed, role, secret)
        )
        conn.commit()
        user_id = cur.lastrowid
        conn.close()

        # حفظ بيانات مؤقتة للـ 2FA
        session["pending_user_id"]    = user_id
        session["pending_user_email"] = safe_email
        session["is_new_register"]    = True

        return redirect("/verify-2fa")

    return render_template("register.html")

# ================= LOGIN =================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email")
        password = request.form.get("password")

        conn = connect_db()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cur.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode("utf-8"), user[3]):
            safe_email = email.replace("@", "_").replace(".", "_")
            session["pending_user_id"]    = user[0]
            session["pending_user_email"] = safe_email
            session["is_new_register"]    = False
            return redirect("/verify-2fa")

        return render_template("login.html", error="Wrong email or password")

    return render_template("login.html")

# ================= VERIFY 2FA =================

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify():
    if "pending_user_id" not in session:
        return redirect("/login")

    is_new   = session.get("is_new_register", False)
    qr_email = session.get("pending_user_email", "")

    if request.method == "POST":
        code = request.form.get("code")

        conn = connect_db()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id=?", (session["pending_user_id"],))
        user = cur.fetchone()
        conn.close()

        if not user:
            return redirect("/login")

        totp = pyotp.TOTP(user[5])

        if totp.verify(code):
            # ✅ توليد JWT token
            token = create_access_token(
                identity={"id": user[0], "role": user[4], "email": user[2]}
            )

            # ✅ مسح الـ pending ورفع الـ session الكاملة
            session.clear()
            session["user_id"] = user[0]
            session["role"]    = user[4]
            session["email"]   = user[2]
            session["name"]    = user[1]
            session["token"]   = token   # للعرض في الـ demo

            return redirect("/dashboard")

        return render_template(
            "verify.html",
            is_new=is_new,
            qr_email=qr_email,
            error="Wrong code, please try again"
        )

    return render_template("verify.html", is_new=is_new, qr_email=qr_email)

# ================= LOGOUT =================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ================= DASHBOARD =================

@app.route("/dashboard")
def dashboard():
    err = require_login()
    if err:
        return err
    return render_template("dashboard.html")

# ================= PROFILE =================

@app.route("/profile")
def profile():
    err = require_login()
    if err:
        return err

    conn = connect_db()
    cur  = conn.cursor()
    cur.execute("SELECT name, email, role FROM users WHERE id=?", (session["user_id"],))
    user = cur.fetchone()
    conn.close()

    return render_template("profile.html", user=user)

# ================= ROLES =================

@app.route("/admin")
def admin():
    err = require_role("Admin")
    if err:
        return err
    return render_template("admin.html")

@app.route("/manager")
def manager():
    err = require_role("Manager")
    if err:
        return err
    return render_template("manager.html")

@app.route("/user")
def user():
    err = require_role("User")
    if err:
        return err
    return render_template("user.html")

# ================= API: عرض التوكن للـ Demo =================

@app.route("/api/token")
def show_token():
    """للـ demo بس — بيعرض التوكن"""
    token = session.get("token")
    if not token:
        return jsonify({"error": "No token — please login first"}), 401
    return jsonify({"token": token})

# ================= RUN =================

if __name__ == "__main__":
    app.run(debug=True)