import os
import sqlite3
from functools import wraps

import jwt
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = "vulnshop-secret"  # INTENTIONAL VULNERABILITY: weak hard-coded session secret.
DB_PATH = os.environ.get("DB_PATH", "/app/data/vulnshop.db")
JWT_SECRET = "secret"  # INTENTIONAL VULNERABILITY: weak hard-coded JWT signing secret.
JWT_ALGORITHM = "HS256"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def query_db(sql, params=(), one=False):
    conn = get_db()
    try:
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        return (rows[0] if rows else None) if one else rows
    finally:
        conn.close()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        email TEXT NOT NULL,
        card_number TEXT,
        api_key TEXT
    );
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        price REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        content TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        total REAL NOT NULL
    );
    """)
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        conn.executemany("INSERT INTO users (username,password,role,email,card_number,api_key) VALUES (?,?,?,?,?,?)", [
            ("admin", "admin123", "admin", "admin@vulnshop.local", "4111111111111111", "VS-ADMIN-API-KEY-001"),
            ("alice", "password1", "user", "alice@vulnshop.local", "5555555555554444", "VS-ALICE-API-KEY-002"),
            ("bob", "password2", "user", "bob@vulnshop.local", "4000000000000002", "VS-BOB-API-KEY-003"),
        ])
        conn.executemany("INSERT INTO products (name,description,price) VALUES (?,?,?)", [
            ("Security Scanner", "A scanner for testing vulnerable applications.", 99.99),
            ("Red Team Hoodie", "A deliberately fictional security-themed hoodie.", 49.99),
            ("Bug Hunter Mug", "A mug for application security engineers.", 14.99),
            ("DAST Lab Kit", "A fictional lab kit for scanner validation.", 149.99),
        ])
        conn.executemany("INSERT INTO reviews (product_id,username,content) VALUES (?,?,?)", [
            (1, "alice", "Great test product."), (2, "bob", "Nice hoodie.")
        ])
        conn.executemany("INSERT INTO orders (user_id,product_id,quantity,total) VALUES (?,?,?,?)", [
            (1,1,1,99.99), (1,3,2,29.98), (2,2,1,49.99), (3,4,1,149.99)
        ])
        conn.commit()
    conn.close()

def create_jwt(user):
    # INTENTIONAL VULNERABILITY: no exp claim; weak hard-coded secret.
    return jwt.encode({"sub": user["id"], "username": user["username"], "role": user["role"]}, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_bearer_token():
    header = request.headers.get("Authorization", "")
    return header[7:].strip() if header.startswith("Bearer ") else None

def decode_vulnerable_jwt(token):
    # INTENTIONAL VULNERABILITY: signature verification explicitly disabled; alg=none accepted; exp not checked.
    return jwt.decode(token, options={"verify_signature": False, "verify_exp": False}, algorithms=["HS256", "none"])

def api_auth(required=True):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = get_bearer_token()
            if not token:
                if required:
                    return jsonify({"error":"missing bearer token","hint":"Authorization: Bearer <jwt>"}),401
                return func(None,*args,**kwargs)
            try:
                claims = decode_vulnerable_jwt(token)
            except Exception as exc:
                # INTENTIONAL VULNERABILITY: verbose error disclosure.
                return jsonify({"error":"invalid token","exception":type(exc).__name__,"details":str(exc)}),401
            return func(claims,*args,**kwargs)
        return wrapper
    return decorator

@app.route("/health")
def health():
    return jsonify({"status":"ok","application":"vulnShop"})

@app.route("/")
def index():
    return render_template("index.html", products=query_db("SELECT * FROM products ORDER BY id"))

@app.route("/login", methods=["GET","POST"])
def login():
    error=None
    if request.method == "POST":
        username=request.form.get("username","")
        password=request.form.get("password","")
        # INTENTIONAL VULNERABILITY: SQL injection authentication bypass.
        sql=f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            user=query_db(sql,one=True)
        except Exception as exc:
            # INTENTIONAL VULNERABILITY: verbose SQL error disclosure.
            error=f"Database error: {type(exc).__name__}: {exc}"
            user=None
        if user:
            session["user_id"]=user["id"]
            session["username"]=user["username"]
            return redirect(url_for("index"))
        error=error or "Invalid username or password."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("index"))

@app.route("/search")
def search():
    q=request.args.get("q","")
    # INTENTIONAL VULNERABILITY: SQL injection in product search.
    sql=f"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
    try: products=query_db(sql)
    except Exception as exc:
        # INTENTIONAL VULNERABILITY: verbose database error disclosure.
        return render_template("search.html",q=q,products=[],error=f"{type(exc).__name__}: {exc}")
    return render_template("search.html",q=q,products=products,error=None)

@app.route("/product")
def product():
    product_id=request.args.get("id","1")
    # INTENTIONAL VULNERABILITY: SQL injection in product lookup.
    sql=f"SELECT * FROM products WHERE id = {product_id}"
    try: item=query_db(sql,one=True)
    except Exception as exc:
        # INTENTIONAL VULNERABILITY: verbose error disclosure.
        return f"<h1>Database error</h1><pre>{type(exc).__name__}: {exc}</pre>",500
    if not item: return "Product not found",404
    reviews=query_db("SELECT * FROM reviews WHERE product_id = ? ORDER BY id DESC",(item["id"],))
    return render_template("product.html",product=item,reviews=reviews)

@app.route("/review", methods=["POST"])
def review():
    # INTENTIONAL VULNERABILITY: CSRF; no anti-CSRF token.
    product_id=request.form.get("product_id","1")
    username=session.get("username","anonymous")
    content=request.form.get("content","")
    conn=get_db(); conn.execute("INSERT INTO reviews (product_id,username,content) VALUES (?,?,?)",(product_id,username,content)); conn.commit(); conn.close()
    return redirect(url_for("product",id=product_id))

@app.route("/account")
def account():
    account_id=request.args.get("id",str(session.get("user_id","")))
    # INTENTIONAL VULNERABILITY: IDOR and SQL injection in account lookup.
    sql=f"SELECT * FROM users WHERE id = {account_id}"
    try: user=query_db(sql,one=True)
    except Exception as exc:
        # INTENTIONAL VULNERABILITY: verbose error disclosure.
        return f"<h1>Account database error</h1><pre>{type(exc).__name__}: {exc}</pre>",500
    if not user: return "User not found",404
    return render_template("account.html",user=user)

@app.route("/account/update", methods=["POST"])
def account_update():
    # INTENTIONAL VULNERABILITY: CSRF; no anti-CSRF token.
    account_id=request.form.get("id","")
    email=request.form.get("email","")
    conn=get_db(); conn.execute("UPDATE users SET email = ? WHERE id = ?",(email,account_id)); conn.commit(); conn.close()
    return redirect(url_for("account",id=account_id))

@app.route("/orders")
def orders():
    user_id=request.args.get("id",str(session.get("user_id","")))
    # INTENTIONAL VULNERABILITY: IDOR and SQL injection in orders lookup.
    sql=f"SELECT orders.id,orders.user_id,orders.product_id,orders.quantity,orders.total,products.name AS product_name FROM orders JOIN products ON products.id = orders.product_id WHERE orders.user_id = {user_id} ORDER BY orders.id"
    try: order_rows=query_db(sql)
    except Exception as exc:
        # INTENTIONAL VULNERABILITY: verbose SQL error disclosure.
        return f"<h1>Orders database error</h1><pre>{type(exc).__name__}: {exc}</pre>",500
    return render_template("orders.html",orders=order_rows,user_id=user_id)

@app.route("/redirect")
def open_redirect():
    destination=request.args.get("next") or request.args.get("url") or "/"
    # INTENTIONAL VULNERABILITY: open redirect; destination is not validated.
    return redirect(destination)

@app.route("/api/login", methods=["POST"])
def api_login():
    data=request.get_json(silent=True) or {}
    username=data.get("username",""); password=data.get("password","")
    # INTENTIONAL VULNERABILITY: SQL injection authentication bypass.
    sql=f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try: user=query_db(sql,one=True)
    except Exception as exc:
        # INTENTIONAL VULNERABILITY: verbose SQL error disclosure.
        return jsonify({"error":"database failure","exception":type(exc).__name__,"details":str(exc),"sql":sql}),500
    if not user: return jsonify({"error":"invalid credentials"}),401
    token=create_jwt(user)
    return jsonify({"token":token,"token_type":"Bearer","user":{"id":user["id"],"username":user["username"],"role":user["role"]}})

@app.route("/api/me", methods=["GET"])
@api_auth()
def api_me(claims):
    return jsonify({"claims":claims})

@app.route("/api/users/<int:user_id>", methods=["GET"])
@api_auth()
def api_get_user(claims,user_id):
    # INTENTIONAL VULNERABILITY: BOLA/IDOR; no ownership check.
    # INTENTIONAL VULNERABILITY: excessive data exposure; returns password/card/API key.
    user=query_db("SELECT id,username,password,role,email,card_number,api_key FROM users WHERE id = ?",(user_id,),one=True)
    if not user: return jsonify({"error":"user not found"}),404
    return jsonify(dict(user))

@app.route("/api/orders/<int:order_id>", methods=["GET"])
@api_auth()
def api_get_order(claims,order_id):
    # INTENTIONAL VULNERABILITY: BOLA/IDOR; no order ownership check.
    order=query_db("SELECT orders.id,orders.user_id,orders.product_id,orders.quantity,orders.total,products.name AS product_name FROM orders JOIN products ON products.id = orders.product_id WHERE orders.id = ?",(order_id,),one=True)
    if not order: return jsonify({"error":"order not found"}),404
    return jsonify(dict(order))

@app.route("/api/users/<int:user_id>", methods=["PUT","PATCH"])
@api_auth()
def api_update_user(claims,user_id):
    data=request.get_json(silent=True) or {}
    allowed_fields=["username","password","role","email","card_number","api_key"]
    updates=[]; values=[]
    for field in allowed_fields:
        if field in data:
            updates.append(f"{field} = ?"); values.append(data[field])
    if not updates: return jsonify({"error":"no update fields supplied"}),400
    # INTENTIONAL VULNERABILITY: mass assignment, including role=admin.
    # INTENTIONAL VULNERABILITY: IDOR; no ownership/authorization check.
    values.append(user_id)
    sql="UPDATE users SET " + ", ".join(updates) + " WHERE id = ?"
    try:
        conn=get_db(); conn.execute(sql,values); conn.commit(); conn.close()
    except Exception as exc:
        # INTENTIONAL VULNERABILITY: verbose error disclosure.
        return jsonify({"error":"database update failed","exception":type(exc).__name__,"details":str(exc)}),500
    user=query_db("SELECT id,username,role,email FROM users WHERE id = ?",(user_id,),one=True)
    return jsonify(dict(user))

@app.route("/api/products", methods=["GET"])
@api_auth()
def api_products(claims):
    search=request.args.get("search","")
    # INTENTIONAL VULNERABILITY: SQL injection through API query parameter.
    sql=f"SELECT id,name,description,price FROM products WHERE name LIKE '%{search}%' OR description LIKE '%{search}%'"
    try: products=query_db(sql)
    except Exception as exc:
        # INTENTIONAL VULNERABILITY: verbose error disclosure.
        return jsonify({"error":"query failed","exception":type(exc).__name__,"details":str(exc),"sql":sql}),500
    return jsonify({"count":len(products),"products":[dict(row) for row in products]})

@app.route("/api/admin/users", methods=["GET"])
@api_auth()
def api_admin_users(claims):
    # INTENTIONAL VULNERABILITY: broken function-level authorization.
    # Role comes from a JWT whose signature is never validated.
    if claims.get("role") != "admin": return jsonify({"error":"admin role required"}),403
    users=query_db("SELECT id,username,role,email,card_number,api_key FROM users ORDER BY id")
    return jsonify({"users":[dict(row) for row in users]})

@app.errorhandler(Exception)
def global_error(error):
    # INTENTIONAL VULNERABILITY: verbose application error disclosure.
    return jsonify({"error":type(error).__name__,"message":str(error)}),500

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0",port=5000,debug=True)  # INTENTIONAL VULNERABILITY: debug mode enabled.
