# Аутентификация на FastAPI

from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response
from typing import Optional
import hmac, hashlib, base64

app = FastAPI()

SECRET_KEY = "f9291e8f70f5a48a2a1c1e45879bf8f1f80291baf22c2377233b05d806ace0ee"
PASSWORD_SALT = "37eb749bb93980399720b899a4a591996cab305f7be607cf55a4472297024911"


def sign_data(data: str) -> str:
    ''' возвращает подписанные данные data'''
    return hmac.new(SECRET_KEY.encode(), msg=data.encode(), digestmod=hashlib.sha256).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    ''' получаем юзернейм из подписанной строки. В итоге мы получим или корректный юзернейм(емайл),
     либо None, если подпись неправильная '''
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username, password):
    ''' для сравнения хеша от введенного пароля с хешем из словаря users '''
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return password_hash == stored_password_hash


# список юзеров с паролями
users = {
    'igor@1.ru':{
        'name': 'Игорь',
        'password': '9420a758ecbd9be18b4082e71d8dbc7c1ba364681c2c15ed5421c135317565fc',
        'balance': 200_000
    }
}


@app.get("/") # главная страница
def index_page(username: Optional[str] = Cookie(default=None)): # читаем подписанные куки
    with open('templates/login.html', 'r') as f:
        login_page = f.read() # считываем шаблон страницы логина и пароля
    if not username: # если куки не прочитаны
        return Response(login_page, media_type="text/html") # отправляем пользователя на страницу входа
    valid_username = get_username_from_signed_string(username)
    if not valid_username: # если юзернейм не корректный (подпись не валидна)
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username") # стираем куки
        return response # и отправляем пользователя на страницу входа
    try: # сравниваем их со словарем users
        user = users[valid_username] # узнаем юзера, если он есть в словаре users
        return Response(f"Привет, {user['name']}!", media_type="text/html") # печатаем страницу приветствия юзера
    except KeyError: # если таких кук нет в словаре
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username") # стираем куки
        return response # отправляем на страницу входа
        
    
@app.post("/login")
def process_login_page(username : str = Form(...), password : str = Form(...)):
    # считываем из формы username и password
    user = users.get(username)  # пытаемся доставть из словаря users нужного нам юзера,
                                # используя его имя, добытое из формы
    if not user or not verify_password(username, password): # если нет такого или хеш пароля не совпадает
        return Response('Я вас не знаю!', media_type="text/html")
    responce = Response(f"Привет, {user['name']}!<br /> Баланс: {user['balance']}",
    media_type="text/html") # если пароль совпадает, печатаем приветствие
    username_signed = base64.b64encode(username.encode()).decode() + '.' + sign_data(username)
    ''' задаем хитрую куку, которая состоит из двух значений, разделенных точкой.
    Первое значение - юзернейм (в нашем случае e-mail), превращенный в зашифрованную строку
    через base64, второе значение - тот же юзернейм - емайл, подписанный функцией sign-data
    с помощью SECRET_KEY '''
    responce.set_cookie(key="username", value=username_signed) # и отправляем куки в браузер
    return responce