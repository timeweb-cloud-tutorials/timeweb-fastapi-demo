from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from cryptography.fernet import Fernet
from pydantic import BaseModel
import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class Variable(BaseModel):
    key: str
    value: str


class UpdateVariable(BaseModel):
    new_value: str

# Генерация ключа шифрования (генерируйте один раз и сохраните)
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", Fernet.generate_key())
fernet = Fernet(ENCRYPTION_KEY)

# Инициализация базы данных
Base = declarative_base()
DATABASE_URL = "sqlite:///./app/db/env_manager.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Инициализация объекта HTTPBasic
security = HTTPBasic()

# Логин и пароль для доступа к странице (желательно хранить в переменных окружения)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "password")


# Функция для проверки логина и пароля
def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Неверные учетные данные",
            headers={"WWW-Authenticate": "Basic"},
        )

# Модель данных
class EnvironmentVariable(Base):
    __tablename__ = "environment_variables"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, nullable=False)
    value = Column(String, nullable=False)


# Настройки
ALLOWED_IPS = ["127.0.0.1", "192.168.0.100", "::ffff:127.0.0.1"]  # Список разрешённых IP
VALID_TOKENS = ["my_difficult_bearer_key", "qwe"]  # Список допустимых Bearer токенов

# Создаем таблицы
Base.metadata.create_all(bind=engine)

# FastAPI приложение
app = FastAPI()

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Разрешить запросы с любых доменов (можно указать конкретные домены)
    allow_credentials=True,
    allow_methods=["*"],  # Разрешить любые методы (GET, POST, PUT, DELETE и т.д.)
    allow_headers=["*"],  # Разрешить любые заголовки
)


# Middleware для проверки IP и токена
class IPAndTokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Пропускать запросы с методом OPTIONS
        if request.method == "OPTIONS":
            response = await call_next(request)
            return response

        # Проверяем, содержит ли путь "api"
        if "api" not in request.url.path:
            response = await call_next(request)
            return response

        # Проверка IP
        client_ip = request.client.host
        if client_ip not in ALLOWED_IPS:
            return JSONResponse(
                {"detail": f"Access denied for IP: {client_ip}"}, status_code=403
            )

        # Проверка Bearer токена
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse({"detail": "Authorization header missing or invalid"}, status_code=401)

        token = auth_header.split(" ")[1]
        if token not in VALID_TOKENS:
            return JSONResponse({"detail": "Invalid or missing token"}, status_code=403)

        # Если проверки прошли, передаем запрос дальше
        response = await call_next(request)
        return response


# Подключение middleware
app.add_middleware(IPAndTokenMiddleware)


# Dependency для работы с сессией базы данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Утилиты шифрования
def encrypt_value(value: str) -> str:
    return fernet.encrypt(value.encode()).decode()


def decrypt_value(value: str) -> str:
    return fernet.decrypt(value.encode()).decode()


# API Endpoints

# Указываем папку, где будут храниться статические файлы (например, HTML)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


# Основной маршрут, который будет отдавать index.html
@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("app/static/index.html", "r") as f:
        return HTMLResponse(content=f.read())


# Маршрут админки
@app.get("/admin", response_class=HTMLResponse)
async def read_admin(credentials: HTTPBasicCredentials = Depends(authenticate)):
    with open("app/static/admin.html", "r") as f:
        return HTMLResponse(content=f.read())


@app.post("/api/variables/")
def add_variable(variable: Variable, db: Session = Depends(get_db)):
    """Добавление новой переменной окружения."""
    encrypted_value = encrypt_value(variable.value)
    env_var = EnvironmentVariable(key=variable.key, value=encrypted_value)
    db.add(env_var)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail="Переменная с таким ключом уже существует")
    return {"message": "Переменная добавлена", "key": variable.key}


@app.get("/api/variables/")
def list_variables(db: Session = Depends(get_db)):
    """Получение списка всех переменных (без расшифровки значений)."""
    variables = db.query(EnvironmentVariable).all()
    return [{"key": var.key} for var in variables]


@app.get("/api/variables/{key}")
def get_variable(key: str, db: Session = Depends(get_db)):
    """Получение значения переменной по ключу."""
    variable = db.query(EnvironmentVariable).filter(EnvironmentVariable.key == key).first()
    if not variable:
        raise HTTPException(status_code=404, detail="Переменная не найдена")
    decrypted_value = decrypt_value(variable.value)
    return {"key": key, "value": decrypted_value}


@app.put("/api/variables/{key}")
def update_variable(key: str, update: UpdateVariable, db: Session = Depends(get_db)):
    """Обновление значения переменной по ключу."""
    variable = db.query(EnvironmentVariable).filter(EnvironmentVariable.key == key).first()
    if not variable:
        raise HTTPException(status_code=404, detail="Переменная не найдена")
    variable.value = encrypt_value(update.new_value)
    db.commit()
    return {"message": "Переменная обновлена", "key": key}


@app.delete("/api/variables/{key}")
def delete_variable(key: str, db: Session = Depends(get_db)):
    """Удаление переменной по ключу."""
    variable = db.query(EnvironmentVariable).filter(EnvironmentVariable.key == key).first()
    if not variable:
        raise HTTPException(status_code=404, detail="Переменная не найдена")
    db.delete(variable)
    db.commit()
    return {"message": "Переменная удалена", "key": key}
