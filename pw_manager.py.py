import random
import json
import sys
import os
import shutil

# Символы для паролей
DIGITS = "0123456789"
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
PUNCTUATION = "!#$%&*+-=?@^_."
AMBIGUOUS = "il1Lo0O"


def get_paths():
    """
    Возвращает (bundled_data_path, persistent_data_path)
    - bundled_data_path: путь к data.json, если он в составе пакета (в PyInstaller _MEIPASS) или в папке скрипта
    - persistent_data_path: путь, куда нужно сохранять изменения (пользовательский AppData)
    """
    if getattr(sys, "frozen", False):
        # Когда упаковано PyInstaller (auto-py-to-exe с onefile/unpacked)
        base_path = (
            sys._MEIPASS
        )  # папка, куда PyInstaller распаковал вспомогательные файлы
    else:
        base_path = os.path.dirname(__file__)

    bundled_data_path = os.path.join(base_path, "data.json")

    # Путь для постоянного хранения (AppData\Roaming\pw_manager\data.json)
    appdata = os.getenv("APPDATA") or os.path.expanduser("~")
    app_folder = os.path.join(appdata, "pw_manager")
    os.makedirs(app_folder, exist_ok=True)
    persistent_data_path = os.path.join(app_folder, "data.json")

    return bundled_data_path, persistent_data_path


def ensure_persistent_data(bundled, persistent):
    """
    Если в persistent нет файла — пытаемся скопировать встроенный bundled (если есть).
    Если bundled отсутствует — создаём пустой JSON.
    """
    if not os.path.exists(persistent):
        if os.path.exists(bundled):
            try:
                shutil.copyfile(bundled, persistent)
            except Exception:
                # На всякий случай — если копирование не удалось, создаём пустой файл
                with open(persistent, "w", encoding="utf-8") as f:
                    json.dump({}, f, ensure_ascii=False, indent=4)
        else:
            with open(persistent, "w", encoding="utf-8") as f:
                json.dump({}, f, ensure_ascii=False, indent=4)


def load_data(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_data(path, data):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=4)


def main():
    bundled, persistent = get_paths()
    ensure_persistent_data(bundled, persistent)

    data = load_data(persistent)

    new_password = "y"

    while new_password != "n":

        try:
            choice = int(input("Список паролей (0) \\ Создать новый (1): "))
        except ValueError:
            print("Неверный ввод. Введите 0 или 1.")
            continue

        if choice == 1:
            login = input("Сервис: ")
            try:
                password_length = int(input("Длина пароля: "))
            except ValueError:
                print("Длина должна быть числом.")
                continue

            var_digits = input("Включать цифры (0-9) y/n: ").lower()
            var_uppercase = input("Включать прописные буквы (A-Z) y/n: ").lower()
            var_lowercase = input("Включать строчные буквы (a-z) y/n: ").lower()
            var_punctuation = input("Включать символы (!#$%&*+-=?@^_.) y/n: ").lower()
            var_ambiguous = input(
                "Исключать неоднозначные символы (il1Lo0O) y/n: "
            ).lower()

            yes = "y"
            symbols = ""
            if var_digits == yes:
                symbols += DIGITS
            if var_uppercase == yes:
                symbols += UPPERCASE
            if var_lowercase == yes:
                symbols += LOWERCASE
            if var_punctuation == yes:
                symbols += PUNCTUATION
            if var_ambiguous == yes:
                symbols = "".join([s for s in symbols if s not in AMBIGUOUS])

            if not symbols:
                print("Ошибка: Вы не выбрали ни одного типа символов!")
                continue

            if len(symbols) < password_length:
                symbols *= (password_length // len(symbols)) + 1

            password = "".join(random.sample(symbols, password_length))

            print(f"Сервис: {login} Пароль: {password}")

            if input("Сохранить? y/n: ").lower() == "y":
                data[login] = password
                save_data(persistent, data)
                print(f"Сохранено: {persistent}")

        else:
            templates = load_data(persistent)
            if templates:
                print("\nСписок сохранённых паролей:\n")
                for k, v in templates.items():
                    print(f"{k.ljust(20)} : {v}")
            else:
                print("Файл с паролями пуст или не найден.")

        new_password = input("Повторим? y/n: ").lower()


if __name__ == "__main__":
    main()
