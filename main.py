import hmac
import base64
import hashlib
import json
from typing import Optional
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

app = FastAPI()
SECRET_KEY = "e132a2bae6fcf8fe802fdb78d8ddd07fda36dae5295e94247cd68920eee7bd5a"
PASS_SALT = "b6cc3cd49b1c4a209a2af73967bafb9dadb5d54a6f320b47c9f8cc184cba4b93"


def verify_pass(username: str, password: str):
    pass_hash = hashlib.sha256((password + PASS_SALT).encode()).hexdigest().lower()
    stored_hash = users[username]["password"]
    return pass_hash == stored_hash


users = {
    "alehandrodol": {
        "name": "Алексей",
        "password": "306cd02af3ed67833c2d6e6e18ac3a3ef45aa9ffd1269ea887266ae36d853728",
        "balance": 322_228
    },
    "niko_dobr": {
        "name": "Николай",
        "password": "4cbe621c1e8044894226f98585d48f962a3f43cb882eae072ecf82181ad1e943",
        "balance": 999_999_999
    }
}


def sign_data(data: str) -> str:
    """Возвращает подписанные данные"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed(signed: str) -> Optional[str]:
    user = signed.split('.')[0]
    sign = signed.split('.')[1]
    try:
        res = base64.b64decode(user).decode()
    except UnicodeDecodeError:
        return None
    valid_sign = sign_data(res)
    if hmac.compare_digest(sign, valid_sign):
        return res
    return None


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open("./templates/index.html", "r") as html:
        index = html.read()
    if not username:
        return Response(index, media_type="text/html")
    valid_username = get_username_from_signed(username)
    try:
        user = users[valid_username]
    except KeyError:
        res = Response(index, media_type="text/html")
        res.delete_cookie("username")
        return res
    return Response(f"Здравствуйте, {user['name']}, ваш баланс {user['balance']}, "
                    f"вы попали по куке", media_type="text/html")


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_pass(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я твоя не понимать"
            }),
            media_type="application/json")
    else:
        response = Response(
            json.dumps({
                "success": True,
                "message": f"Привет, {user['name']}, ваш баланс: {user['balance']}"
            }),
            media_type="application/json")
        cookie = f"{base64.b64encode(username.encode()).decode()}.{sign_data(username)}"
        response.set_cookie(key="username", value=cookie)
        return response
