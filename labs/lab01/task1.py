import os
import random
import sys

# Підключення спільного модуля даних
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Початковий список паролів для перевірки
passwords = [
    "password123",
    "Qwerty!2023",
    "admin",
    "MyP@ssw0rd",
    "123456",
    "SecurePass!",
    "test",
    "P@ssw0rd123",
    "welcome",
    "StrongP@ss1",
    "qwerty",
]

# Критерії складності пароля
criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

# Множина заборонених паролів
forbidden_passwords = {"password", "123456", "admin", "test", "welcome", "qwerty"}

# Випадкове дублювання 3 паролів у списку
initial_len = len(passwords)
for _ in range(3):
    rand_idx = random.randint(0, initial_len - 1)
    passwords.append(passwords[rand_idx])

results = []
min_len = criteria["min_length"]

# Аналіз надійності кожного пароля
for pwd in passwords:
    # Перевірка наявності необхідних категорій символів
    has_digit = any(c.isdigit() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_special = any(not c.isalnum() and not c.isspace() for c in pwd)

    # Перевірка виконання базових вимог безпеки
    meets_criteria = (
        len(pwd) >= min_len
        and (not criteria["require_digits"] or has_digit)
        and (not criteria["require_upper"] or has_upper)
        and (not criteria["require_special"] or has_special)
    )

    # Класифікація рівня надійності пароля
    if pwd in forbidden_passwords or len(pwd) < min_len:
        strength = "Заборонений"
    elif meets_criteria and len(pwd) >= min_len + 4 and passwords.count(pwd) == 1:
        strength = "Дуже сильний"
    elif meets_criteria:
        strength = "Сильний"
    elif len(pwd) >= min_len and (has_digit or has_upper or has_lower or has_special):
        strength = "Середній"
    else:
        strength = "Слабкий"

    results.append((pwd, len(pwd), strength))

# Форматоване виведення результатів оцінки
print("=" * 56)
print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
print("=" * 56)
print(f"{'№':<4} | {'Пароль':<18} | {'Довжина':<8} | {'Оцінка надійності'}")
print("-" * 56)

for idx, (pwd, length, strength) in enumerate(results, start=1):
    print(f"{idx:<4} | {pwd:<18} | {length:<8} | {strength}")

print("=" * 56)
