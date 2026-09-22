import os
import sys

# Імпорт індивідуальних параметрів студента
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# База даних користувачів із атрибутами доступу
users = {
    "sysadmin02": {
        "role": "system_admin",
        "clearance": 4,
        "department": "Infrastructure",
        "active": True,
    },
    "analyst234": {
        "role": "security_analyst",
        "clearance": 3,
        "department": "SOC",
        "active": True,
    },
    "developer567": {
        "role": "developer",
        "clearance": 2,
        "department": "Development",
        "active": True,
    },
    "intern890": {"role": "intern", "clearance": 1, "department": "HR", "active": True},
    "external123": {
        "role": "external",
        "clearance": 1,
        "department": "Vendor",
        "active": False,
    },
}

# Ресурси та відповідний мінімальний рівень доступу
resources = [
    ("prod_database", 4),
    ("dev_environment", 2),
    ("documentation", 1),
    ("source_code", 3),
    ("server_configs", 4),
    ("test_data", 2),
    ("compliance_docs", 3),
    ("system_logs", 4),
    ("project_files", 2),
    ("public_wiki", 1),
]

# Текстові назви рівнів безпеки
security_levels = ("Open", "Internal", "Restricted", "Top Secret")

# Список заблокованих облікових записів
blocked_users = {"external123", "old_account", "test_user"}

# Виведення структурованої таблиці ресурсів
print("=" * 60)
print("СПИСОК РЕСУРСІВ СИСТЕМИ ТА ЇХНІ РІВНІ ДОСТУПУ")
print("=" * 60)
print(f"{'Назва ресурсу':<20} | {'Числовий':<9} | {'Рівень безпеки'}")
print("-" * 60)

for res_name, res_level in resources:
    level_text = security_levels[res_level - 1]
    print(f"{res_name:<20} | {res_level:<9} | {level_text}")

print("\n" + "=" * 60)
print("РЕЗУЛЬТАТИ ПЕРЕВІРКИ ДОСТУПУ")
print("=" * 60)


def check_access(username: str, resource: tuple) -> str:
    # Перевіряє права доступу користувача до ресурсу за моделлю MAC/RBAC
    res_name, res_level = resource

    # Перевірка наявності користувача в базі
    if username not in users:
        return "DENY (User not found)"
    # Перевірка блокування облікового запису
    if username in blocked_users:
        return "DENY (User is blocked)"

    user_info = users[username]

    # Перевірка активності акаунту
    if not user_info.get("active", False):
        return "DENY (Account inactive)"
    # Порівняння рівня допуску користувача з рівнем ресурсу
    if user_info.get("clearance", 0) >= res_level:
        return "ALLOW"
    else:
        return "DENY (Insufficient clearance)"


# Формування тестового списку включно з неіснуючим користувачем
test_users_list = list(users.keys()) + ["test"]

# Запуск перевірки доступу
for username in test_users_list:
    print(f"\n--- Перевірка для користувача: {username} ---")
    for res in resources:
        res_name, _ = res
        result = check_access(username, res)
        print(f"user={username} resource={res_name} |-> {result}")
