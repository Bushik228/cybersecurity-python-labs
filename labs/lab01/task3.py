import csv
import hashlib
import json
import os
import sys
from datetime import datetime

# Імпорт номера варіанту студента
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER

# Константи конфігурації
MIN_LEN = 10
SALT = f"{VARIANT_NUMBER:05d}"  # Персональна сіль (для вар. 2: '00002')
DATA_DIR = "labs/lab01/data"
CSV_PATH = os.path.join(DATA_DIR, "users.csv")
JSON_PATH = os.path.join(DATA_DIR, "log.json")

# База користувачів у пам'яті
users_db = []


# Власний виняток для помилок валідації паролів
class ValidationError(Exception):
    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    # Генерує SHA3-224 хеш від пароля із сіллю з попередньою валідацією
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми")

    if len(password) < MIN_LEN:
        raise ValidationError(f"Пароль має містити щонайменше {MIN_LEN} символів")

    combined = (password + salt).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def log_event(func):
    """Декоратор для запису спроб входу у форматі JSON."""

    def wrapper(*args, **kwargs):
        # Визначення імені користувача з переданих аргументів
        username = kwargs.get("username")
        if not username and len(args) > 0:
            username = args[0]

        result = "failure"
        try:
            res = func(*args, **kwargs)
            if res:
                result = "success"
            return res
        except Exception:
            result = "failure"
            raise
        finally:
            # Гарантоване логування результату події
            os.makedirs(DATA_DIR, exist_ok=True)
            log_data = {
                "event": "login",
                "user": str(username) if username else "",
                "result": result,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args),
                "kwargs": kwargs,
            }

            logs = []
            if os.path.exists(JSON_PATH):
                try:
                    with open(JSON_PATH, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except Exception:
                    logs = []

            logs.append(log_data)
            with open(JSON_PATH, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)

    return wrapper


def create_user(username, password):
    # Створює запис користувача з гешованим паролем
    return (username, generate_hash(password, salt=SALT))


def create_users(users_list):
    # Створює CSV-файл та записує список облікових записів
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for user, pwd in users_list:
            writer.writerow(create_user(user, pwd))


def read_users():
    # Зчитує облікові дані з CSV у users_db та виводить їх у табличному вигляді
    global users_db
    users_db = []
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if row:
                users_db.append((row[0], row[1]))

    print(f"\n{'Користувач':<15} | {'Хеш (SHA-256)':<64}")
    print("-" * 82)
    for u, h in users_db:
        print(f"{u:<15} | {h:<64}")
    print("-" * 82 + "\n")


@log_event
def login(username: str, password: str) -> bool:
    # Автентифікує користувача шляхом порівняння обчисленого хешу з базою
    if not username or not password:
        raise ValueError("Логін і пароль обов'язкові")

    user_hash = generate_hash(password, salt=SALT)

    for db_user, db_hash in users_db:
        if db_user == username and db_hash == user_hash:
            return True
    return False


def main():
    # 10 початкових облікових записів для реєстрації
    users_to_register = (
        ("admin", "Admin12345"),
        ("vlad", "PassSecure1"),
        ("student", "Student2026"),
        ("guest", "GuestPass1"),
        ("moderator", "ModStrong9"),
        ("tester", "TestPassQ8"),
        ("analyst", "AnalystSafe7"),
        ("security", "CyberSec002"),
        ("operator", "OperSystem4"),
        ("backup", "BackupKey99"),
    )

    # Обробка винятків під час операцій введення-виведення та валідації
    try:
        create_users(users_to_register)
        read_users()

        # Тестування автентифікації користувачів
        print("[+] Спроба 1 (успіх):", login("admin", "Admin12345"))
        print("[-] Спроба 2 (невірний пароль):", login("admin", "WrongPass123"))
        print("[-] Спроба 3 (невідомий юзер):", login("unknown", "Pass12345"))

    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"Помилка файлової системи: {e}")
    except (ValidationError, ValueError) as e:
        print(f"Помилка валідації даних: {e}")


if __name__ == "__main__":
    main()
