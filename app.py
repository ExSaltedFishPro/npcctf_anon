import time
from flask import Flask, redirect, render_template_string, request, jsonify, render_template, send_file, make_response
import jwt
import uuid
import hashlib
import pyotp
import qrcode
from io import BytesIO
import random
import os
from selenium import webdriver


try:
    with open("/flag", "w") as f:
        f.write(os.environ.pop("FLAG", "flag{test_flag}"))
except:
    pass
def generate_codes():
    return "-".join(uuid.uuid4().hex[:4] for _ in range(5))

JWT_SECRET = uuid.uuid4().hex
ANON_token = jwt.encode({"username": "anon","perm": "admin"}, JWT_SECRET, algorithm="HS256")
print(f"ANON_token: {ANON_token}")
try:
    os.remove("2fa/anon.png")
except FileNotFoundError:
    pass

userDB = {
    "anon": {"password": hashlib.md5(JWT_SECRET.encode()).hexdigest(), "perm": "admin", "balance": 10},
}

users_2fa_keys = {}

itemDB = [
    {"id": "01","name": "春日影", "price": 10000, "stock": 1, "codes": [generate_codes() for _ in range(1)]},
    {"id": "02","name": "迷星叫", "price": 20000, "stock": 1, "codes": [generate_codes() for _ in range(1)]},
]

commentsDB = [
    {"username": "喜欢捡石头的高木公火丁", "comment": "Anon chan的平台好棒！", "rating": 5, "reply": "谢谢支持"},
    {"username": "喜欢蓝毛", "comment": "取名品味还是很差", "rating": 3, "reply": "我觉得还行啊"},
    {"username": "灯suki", "comment": "竟敢敷衍灯？", "rating": 1, "reply": "哈？"},
]

couponDB = [
    {"type": "percentage", "value": 10, "code": "ANONTOKYO"},
]



def generate_2fa_secret(user_name):
    """为用户生成 2FA 密钥和二维码"""
    user_id = user_name
    totp = pyotp.TOTP(pyotp.random_base32())
    secret = totp.secret
    users_2fa_keys[user_id] = secret
    uri = totp.provisioning_uri(name=user_id, issuer_name="Anon Store")
    qr = qrcode.make(uri)
    img_byte_arr = BytesIO()
    qr.save(img_byte_arr)
    img_byte_arr.seek(0)
    return secret, img_byte_arr

def verify_2fa_code(user_id, code):
    """验证用户输入的 2FA 动态码"""
    if user_id not in users_2fa_keys:
        return False
    totp = pyotp.TOTP(users_2fa_keys[user_id])
    return totp.verify(code)

def save2fa_qrcode(username):
    secret, img_byte_arr = generate_2fa_secret(username)
    with open(f"./2fa/{username}.png", "wb") as f:
        f.write(img_byte_arr.read()) 
    return secret

def getBalance(username):
    try:
        return userDB[username]["balance"]
    except:
        return 0




app = Flask(__name__)
save2fa_qrcode("anon")


@app.route("/", methods=["GET"])
def index():
    token = request.cookies.get("Authorization")
    if token:
        print("token: "+token)
        try:
            datas  = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            username = datas.get("username")
            return render_template("index.html"
                                   ,username=username
                                   ,balance=getBalance(username)
                                   ,items=itemDB
                                   ,comments=commentsDB)
        except jwt.ExpiredSignatureError:
            resp = make_response(redirect("/login"))
            resp.set_cookie("Authorization", "")
            return resp
        except jwt.InvalidTokenError:
            resp = make_response(redirect("/login"))
            resp.set_cookie("Authorization", "")
            return resp
    else:
        return render_template("login.html")


@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html")

@app.route("/api/<action>", methods=["POST"])
def api(action):
    if action == "login":
        datas = request.get_json()
        username = datas.get("username")
        password = datas.get("password")
        twofaCode = datas.get("twofaCode")
        if userDB.get(username) and userDB[username]["password"] == hashlib.md5(password.encode()).hexdigest():
            token = jwt.encode({"username": username, "perm": userDB[username]["perm"]}, JWT_SECRET, algorithm="HS256")
            # 2FA
            if not verify_2fa_code(username, twofaCode):
                return jsonify({"error": "Invalid 2FA code"}), 401
            resp = make_response(redirect("/"))
            resp.set_cookie("Authorization", token)
            if userDB[username]["perm"] == "admin":
                resp = make_response(redirect("/admin"))
                resp.set_cookie("Authorization", token)
                return resp
            return resp
        else:
            return jsonify({"error": "Invalid username or password"}), 401
    elif action == "register":
        datas = request.get_json()
        username = datas.get("username")
        # security check
        for i in username:
            if not str.isalnum(i):
                return jsonify({"error": "Invalid username"}), 400
        password = datas.get("password")
        if userDB.get(username):
            return jsonify({"error": "User already exists"}), 400
        userDB[username] = {"password": hashlib.md5(password.encode()).hexdigest(), "perm": "customer", "balance": 0}
        save2fa_qrcode(username)
        return render_template("bind2fa.html", username=username)
    elif action == "comment":
        datas = request.get_json()
        username = datas.get("username")
        comment = datas.get("comment")
        rating = datas.get("rating")
        if int(rating) <= 3:
            reply = random.choice(["懒得喷", "哈？"])
        else:
            reply = random.choice(["谢谢支持"])
        # security check
        for i in username:
            if not str.isalnum(i):
                return jsonify({"error": "Invalid username"}), 400
        if str(rating) not in ["1", "2", "3", "4", "5"]:
            return jsonify({"error": "Invalid rating"}), 400
        for i in comment:
            if i in ["{", "}", "[", "]", "&", "|", "$", "`", "*", "?", "!", "#", "%", "@"]:
                return jsonify({"error": "Invalid comment"}), 400
        commentsDB.append({"username": username, "comment": comment, "rating": rating, "reply": reply})
        return jsonify({"message": "Comment added"}), 200
    elif action == "pay":
        datas = request.get_json()
        try:
            username = jwt.decode(request.cookies.get("Authorization"), JWT_SECRET, algorithms=["HS256"]).get("username")
        except:
            return jsonify({"error": "Unauthorized"}), 401
        item_id = datas.get("item")
        
        for item in itemDB:
            if item["id"] == item_id:
                price = item["price"]
                if item["stock"] > 0:
                    item["stock"] -= 1
                    couponCode = datas.get("couponCode")
                    if couponCode:
                        price = float(item["price"])
                        for c in couponDB:
                            if c["code"] == couponCode:
                                if c["type"] == "percentage":
                                    price = price * (1 - int(c["value"]) / 100)
                                elif c["type"] == "amount":
                                    price = price - int(c["value"])
                                break
                    if userDB[username]["balance"] < price:
                        return jsonify({"error": "余额不足"}), 400
                    userDB[username]["balance"] -= price
                    with open("templates/success.html", "rb") as f:
                        success_html = f.read().decode(encoding="utf-8")
                    if item_id == "01":
                        music = "2097486090"
                    elif item_id == "02":
                        music = "2097485069"
                    return render_template_string(success_html.replace(r"{{code}}", item["codes"].pop()), music=music, item=item)
                else:
                    return jsonify({"error": "库存不足"}), 400
        return jsonify({"error": "未找到该物品"}), 404
    elif action == "coupon":
        datas = request.get_json()
        try:
            username = jwt.decode(request.cookies.get("Authorization"), JWT_SECRET, algorithms=["HS256"]).get("username")
        except:
            return jsonify({"error": "Unauthorized"}), 401
        typ = datas.get("type")
        val = datas.get("value")
        if typ == "percentage":
            if int(val) > 100 or int(val) < 0:
                return jsonify({"error": "Invalid value"}), 400
            couponDB.append({"type": typ, "value": val, "code": generate_codes()})
        elif typ == "amount":
            if int(val) < 0:
                return jsonify({"error": "Invalid value"}), 400
            couponDB.append({"type": typ, "value": val, "code": generate_codes()})
        else:
            return jsonify({"error": "Invalid type"}), 400
        return jsonify({"coupon": couponDB[-1]["code"]}), 200
    elif action == "addkey":
        datas = request.get_json()
        username = request.cookies.get("Authorization")
        username = jwt.decode(username, JWT_SECRET, algorithms=["HS256"]).get("username")
        key = datas.get("code")
        twoFactorAuth = datas.get("twoFactorAuth")
        # admin only
        if jwt.decode(request.cookies.get("Authorization"), JWT_SECRET, algorithms=["HS256"]).get("perm") != "admin":
            return jsonify({"error": "Unauthorized"}), 401
        # auth
        if not verify_2fa_code(username, twoFactorAuth):
            return jsonify({"error": "Invalid 2FA code"}), 401
        for i in itemDB:
            if i["id"] == datas.get("id"):
                i["codes"].append(key)
                i["stock"] += 1
                return jsonify({"message": "Key added"}), 200
        return jsonify({"error": "Item not found"}), 404



@app.route("/2faqrcode/<username>", methods=["GET"])
def get2faQrcode(username):
    #security check
    for i in username:
        if not str.isalnum(i):
            return jsonify({"error": "insecure filename"}), 400
    return send_file(f"2fa/{username}.png")

@app.route("/pics/<id>", methods=["GET"])
def pics(id):
    #security check
    for i in id:
        if not str.isnumeric(i):
            return jsonify({"error": "insecure filename"}), 400
    return send_file(f"pics/{id}.jpg")

@app.route("/detail/<id>", methods=["GET"])
def detail(id):
    if request.cookies.get("Authorization"):
        username = jwt.decode(request.cookies.get("Authorization"), JWT_SECRET, algorithms=["HS256"]).get("username")
        balance = getBalance(username)
    else:
        balance = 0
    for item in itemDB:
        if item["id"] == id:
            return render_template("payment.html", item=item, balance=balance)
    return "Not found", 404

@app.route("/admin", methods=["GET"])
def admin():
    token = request.cookies.get("Authorization")
    if token:
        try:
            datas  = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            username = datas.get("username")
            if datas.get("perm") == "admin":
                return render_template("admin.html")
            else:
                return "Unauthorized", 401
        except jwt.ExpiredSignatureError:
            resp = make_response(redirect("/login"))
            resp.set_cookie("Authorization", "")
            return resp
        except jwt.InvalidTokenError:
            resp = make_response(redirect("/login"))
            resp.set_cookie("Authorization", "")
            return resp
    else:
        return render_template("login.html")
    
@app.route("/reply", methods=["GET"])
def reply():
    
    options = webdriver.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")
    options.headless = True
    selenium_url = "http://127.0.0.1:4444/wd/hub"

    driver = webdriver.Remote(command_executor=selenium_url, options=options)

    driver.get("http://127.0.0.1:5000/logout")
    time.sleep(1)
    driver.add_cookie({"name": "Authorization", "value": ANON_token})
    driver.get("http://127.0.0.1:5000/")
    time.sleep(1)
    driver.quit()
    return redirect("/")

@app.route("/logout", methods=["GET"])
def logout():
    resp = make_response(redirect("/"))
    resp.set_cookie("Authorization", "")
    return resp

@app.route("/clear", methods=["GET"])
def clear():
    global commentsDB
    commentsDB = [
    {"username": "喜欢捡石头的高木公火丁", "comment": "Anon chan的平台好棒！", "rating": 5, "reply": "谢谢支持"},
    {"username": "喜欢蓝毛", "comment": "取名品味还是很差", "rating": 3, "reply": "我觉得还行啊"},
    {"username": "灯suki", "comment": "竟敢敷衍灯？", "rating": 1, "reply": "哈？"},
]
    return redirect("/")

@app.route("/favicon.ico", methods=["GET"])
def favicon():
    return send_file("./pics/favicon.ico")

app.run(host="0.0.0.0", port=5000, threaded=True)