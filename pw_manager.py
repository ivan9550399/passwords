import os
import json
import base64
import secrets
import time
import re
import logging
from datetime import date
from getpass import getpass
from pathlib import Path
from logging.handlers import RotatingFileHandler
from prettytable import PrettyTable
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from termcolor import colored


# Конфигурация приложения: пути, логирование и символы для паролей
class Config:
    APP_FOLDER = Path(os.getenv("APPDATA", os.path.expanduser("~"))) / "pw_manager"
    USERS_FOLDER = APP_FOLDER / "users"
    LOG_FILE = APP_FOLDER / "pw_manager.log"
    SALT_FILE = "salt.bin"
    DATA_FILE = "data.json"
    PASSWORD_CHARS = {
        "digits": "0123456789",
        "lowercase": "abcdefghijklmnopqrstuvwxyz",
        "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "punctuation": "!#$%&*+-=?@^_.",
        "ambiguous": "il1Lo0O",
    }

    def __init__(self):
        # Создание директорий и настройка логирования
        self.APP_FOLDER.mkdir(exist_ok=True)
        self.USERS_FOLDER.mkdir(exist_ok=True)
        handler = RotatingFileHandler(
            self.LOG_FILE,
            maxBytes=50 * 1024 * 1024,  # 50 МБ
            backupCount=1,
            encoding="utf-8",
        )
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logging.basicConfig(
            handlers=[handler],
            level=logging.INFO
        )


# Класс для шифрования/дешифрования данных с использованием Fernet
class Encryptor:
    def __init__(self, master_password: str, salt: bytes):
        # Инициализация Fernet с производным ключом
        self.fernet = Fernet(self._derive_key(master_password, salt))

    @staticmethod
    def _derive_key(master_password: str, salt: bytes) -> bytes:
        # Генерация ключа из мастер-пароля с PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    def encrypt(self, data: str) -> str:
        # Шифрование строки
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, encrypted: str) -> str:
        # Дешифрование строки с обработкой ошибок
        try:
            return self.fernet.decrypt(encrypted.encode()).decode()
        except InvalidToken:
            return "[Ошибка расшифровки]"


# Класс пользователя: управление данными и файлами
class User:
    def __init__(self, username: str, config: Config):
        # Инициализация путей и загрузка данных
        self.username = username
        self.path = config.USERS_FOLDER / username
        self.salt_path = self.path / config.SALT_FILE
        self.data_path = self.path / config.DATA_FILE
        self.data = self._load_data()

    def _load_data(self) -> dict:
        # Загрузка JSON-данных с обработкой ошибок
        if not self.data_path.exists():
            return {}
        try:
            if self.data_path.stat().st_size == 0:
                raise ValueError("Файл данных пустой.")
            with self.data_path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError, IOError) as e:
            logging.error(f"Ошибка чтения файла {self.data_path}: {e}")
            print(
                colored(
                    f"Ошибка чтения данных: {e}. Данные пользователя повреждены.", "red"
                )
            )
            if PasswordManager._ask_yes_no("Сбросить данные пользователя? y/n: "):
                self.reset()
            return {}

    def save_data(self) -> None:
        # Сохранение данных в JSON
        try:
            with self.data_path.open("w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=4)
        except IOError as e:
            logging.error(f"Ошибка записи файла {self.data_path}: {e}")
            print(colored(f"Ошибка записи данных: {e}", "red"))

    def reset(self) -> None:
        # Сброс данных пользователя
        try:
            for file in (self.salt_path, self.data_path):
                if file.exists():
                    file.unlink()
            if not any(self.path.iterdir()):
                self.path.rmdir()
            print(colored("\n🧹 Все данные пользователя удалены.", "green"))
            logging.info(f"Данные пользователя {self.username} удалены.")
        except OSError as e:
            logging.error(f"Ошибка удаления данных пользователя {self.path}: {e}")
            print(colored(f"Ошибка удаления данных: {e}", "red"))

    def has_valid_data(self) -> bool:
        # Проверка наличия файлов соли и данных
        return self.salt_path.exists() and self.data_path.exists()


# Основной класс менеджера паролей
class PasswordManager:
    def __init__(self):
        # Инициализация конфигурации
        self.config = Config()
        self.user = None
        self.encryptor = None

    @staticmethod
    def _ask_yes_no(prompt: str) -> bool:
        # Вопрос с да/нет ответом
        while True:
            ans = input(prompt).strip().lower()
            if ans in ("y", "n"):
                return ans == "y"
            print(colored("Введите 'y' или 'n'.", "yellow"))

    @staticmethod
    def _mask_password_input(prompt: str) -> str:
        # Ввод пароля с маскировкой
        password = getpass(prompt, stream=None)
        if password:
            print(f"\033[1A\033[K{prompt} {'*' * len(password)}")
        return password

    def _generate_password(
        self,
        length: int,
        use_digits: bool = True,
        use_upper: bool = True,
        use_lower: bool = True,
        use_punct: bool = True,
        exclude_ambiguous: bool = False,
    ) -> str:
        # Генерация случайного пароля
        chars = ""
        if use_digits:
            chars += self.config.PASSWORD_CHARS["digits"]
        if use_upper:
            chars += self.config.PASSWORD_CHARS["uppercase"]
        if use_lower:
            chars += self.config.PASSWORD_CHARS["lowercase"]
        if use_punct:
            chars += self.config.PASSWORD_CHARS["punctuation"]
        if exclude_ambiguous:
            chars = "".join(
                c for c in chars if c not in self.config.PASSWORD_CHARS["ambiguous"]
            )
        if not chars:
            raise ValueError("Нет доступных символов для генерации пароля")
        return "".join(secrets.choice(chars) for _ in range(length))

    def _get_password(self) -> str:
        # Получение пароля: генерация или ручной ввод
        if self._ask_yes_no("Генерировать пароль автоматически? (y/n): "):
            while True:
                length = None
                while length is None:
                    try:
                        length = int(input("Длина пароля: ").strip())
                        if length <= 0:
                            print(colored("Длина пароля должна быть больше 0.", "red"))
                            length = None
                    except ValueError:
                        print(colored("Нужно число.", "red"))
                use_digits = self._ask_yes_no("Включать цифры? y/n: ")
                use_upper = self._ask_yes_no("Включать большие буквы? y/n: ")
                use_lower = self._ask_yes_no("Включать маленькие буквы? y/n: ")
                use_punct = self._ask_yes_no("Включать символы? y/n: ")
                exclude_ambiguous = self._ask_yes_no(
                    "Исключать похожие символы (il1Lo0O)? y/n: "
                )
                # Проверка на наличие хотя бы одного типа символов
                chars = ""
                if use_digits:
                    chars += self.config.PASSWORD_CHARS["digits"]
                if use_upper:
                    chars += self.config.PASSWORD_CHARS["uppercase"]
                if use_lower:
                    chars += self.config.PASSWORD_CHARS["lowercase"]
                if use_punct:
                    chars += self.config.PASSWORD_CHARS["punctuation"]
                if exclude_ambiguous:
                    chars = "".join(
                        c
                        for c in chars
                        if c not in self.config.PASSWORD_CHARS["ambiguous"]
                    )
                if not chars:
                    print(
                        colored("Вы должны выбрать хотя бы один тип символов.", "red")
                    )
                    continue  # Повтор вопроса
                break  # Выходим из внешнего while, если chars не пуст
            while True:
                pwd = self._generate_password(
                    length,
                    use_digits,
                    use_upper,
                    use_lower,
                    use_punct,
                    exclude_ambiguous,
                )
                print(f"\nПароль: {pwd}\n")
                if self._ask_yes_no("Нравится? (y/n): "):
                    return pwd
                print("\nГенерирую новый...\n")
        else:
            while True:
                pwd = input("Введите пароль вручную: ").strip()
                if pwd:
                    return pwd
                print(colored("Пароль не может быть пустым.", "red"))

    def _show_passwords(self) -> None:
        # Отображение сохраненных паролей в таблице
        if not self.user.data or len(self.user.data) == 1 and "_test" in self.user.data:
            print("\nПаролей нет.")
            return
        table = PrettyTable(["Сервис", "Пароль", "Дата"])
        for site in sorted(self.user.data.keys()):
            if site == "_test":
                continue
            info = self.user.data[site]
            pwd = self.encryptor.decrypt(info["password"])
            table.add_row([site, pwd, info.get("created", "")])
        print("\n")
        print(table)

    def _save_password(self, site: str, password: str) -> None:
        # Сохранение пароля с датой создания
        today = date.today().strftime("%d.%m.%Y")
        self.user.data[site] = {
            "password": self.encryptor.encrypt(password),
            "created": today,
        }
        self.user.save_data()

    def create_user(self) -> bool:
        # Создание нового пользователя с мастер-паролем
        while True:
            username = input("\nВведите имя нового пользователя: ").strip()
            if not username:
                print(colored("Имя не может быть пустым.", "red"))
                continue
            self.user = User(username, self.config)
            if self.user.salt_path.exists():
                print(colored("Пользователь уже существует.", "yellow"))
                if self._ask_yes_no("Перезаписать? y/n: "):
                    self.user.reset()
                else:
                    continue
            self.user.path.mkdir(exist_ok=True)
            break
        print(f"Создание мастер-пароля для {username}")
        while True:
            m1 = self._mask_password_input("Введите пароль: ")
            if len(m1) < 3:
                print(colored("Пароль должен быть не менее 3 символов.", "red"))
                continue
            m2 = self._mask_password_input("Повторите пароль: ")
            if m1 != m2:
                print(colored("Пароли не совпадают.", "red"))
                continue
            break
        salt = os.urandom(16)
        try:
            with self.user.salt_path.open("wb") as f:
                f.write(salt)
        except IOError as e:
            logging.error(f"Ошибка записи соли для {username}: {e}")
            print(colored(f"Ошибка записи соли: {e}", "red"))
            return False
        self.encryptor = Encryptor(m1, salt)
        self.user.data = {
            "_test": {
                "password": self.encryptor.encrypt("test"),
                "created": date.today().strftime("%d.%m.%Y"),
            }
        }
        self.user.save_data()
        print(colored(f"\n✅ Пользователь {username} создан.", "green"))
        logging.info(f"Пользователь {username} создан.")
        return True

    def change_master_password(self) -> bool:
        # Изменение мастер-пароля с перешифровкой данных
        print(f"\nИзменение мастер-пароля для {self.user.username}")
        while True:
            old_password = self._mask_password_input("Введите текущий пароль: ")
            try:
                with self.user.salt_path.open("rb") as f:
                    salt = f.read()
                test_encryptor = Encryptor(old_password, salt)
                if (
                    test_encryptor.decrypt(
                        self.user.data.get("_test", {}).get("password", "")
                    )
                    != "test"
                ):
                    raise InvalidToken
                break
            except InvalidToken:
                print(colored("Неверный текущий пароль.", "red"))
                if not self._ask_yes_no("Попробовать снова? y/n: "):
                    return False
        while True:
            m1 = self._mask_password_input("Введите новый пароль: ")
            if len(m1) < 3:
                print(colored("Пароль должен быть не менее 3 символов.", "red"))
                continue
            m2 = self._mask_password_input("Повторите новый пароль: ")
            if m1 != m2:
                print(colored("Пароли не совпадают.", "red"))
                continue
            break
        new_salt = os.urandom(16)
        new_encryptor = Encryptor(m1, new_salt)
        old_data = self.user.data
        self.user.data = {}
        for site, info in old_data.items():
            if site == "_test":
                self.user.data[site] = {
                    "password": new_encryptor.encrypt("test"),
                    "created": info["created"],
                }
            else:
                pwd = test_encryptor.decrypt(info["password"])
                if pwd != "[Ошибка расшифровки]":
                    self.user.data[site] = {
                        "password": new_encryptor.encrypt(pwd),
                        "created": info["created"],
                    }
        try:
            with self.user.salt_path.open("wb") as f:
                f.write(new_salt)
            self.user.save_data()
            self.encryptor = new_encryptor
            print(colored("\n✅ Мастер-пароль изменён.", "green"))
            logging.info(f"Пользователь {self.user.username} изменил мастер-пароль.")
            return True
        except IOError as e:
            logging.error(f"Ошибка записи соли для {self.user.username}: {e}")
            print(colored(f"Ошибка записи соли: {e}", "red"))
            return False

    def login(self) -> bool:
        # Авторизация пользователя
        users = [
            user
            for user in self.config.USERS_FOLDER.iterdir()
            if User(user.name, self.config).has_valid_data()
        ]
        if not users:
            print(colored("\nНет зарегистрированных пользователей.", "yellow"))
            return False
        print("\nДоступные пользователи:")
        for i, user in enumerate(users, 1):
            print(f"{i}. {user.name}")
        print("0. Назад")
        try:
            choice = int(input("\nВыберите пользователя: "))
            if choice == 0:
                return False
            self.user = User(users[choice - 1].name, self.config)
        except (ValueError, IndexError):
            print(colored("Неверный выбор.", "red"))
            return False
        try:
            with self.user.salt_path.open("rb") as f:
                salt = f.read()
        except IOError as e:
            logging.error(f"Ошибка чтения соли для {self.user.username}: {e}")
            print(colored(f"Ошибка чтения соли: {e}", "red"))
            return False
        for attempt in range(5):
            master = self._mask_password_input(
                f"Введите пароль ({self.user.username}): "
            )
            self.encryptor = Encryptor(master, salt)
            test_password = self.user.data.get("_test", {}).get("password", "")
            if not test_password:
                print(colored("Ошибка: данные пользователя повреждены.", "red"))
                logging.error(f"Повреждены данные пользователя {self.user.username}.")
                return False
            try:
                if self.encryptor.decrypt(test_password) != "test":
                    raise InvalidToken
                print(colored("\n✅ Доступ разрешён.", "green"))
                logging.info(f"Пользователь {self.user.username} вошёл в систему.")
                return True
            except InvalidToken:
                print(colored("❌ Неверный пароль.", "red"))
                time.sleep(1)
                continue
        print(colored("🚫 Превышено количество попыток входа.", "red"))
        logging.warning(f"Превышено количество попыток входа для {self.user.username}.")
        return False

    def user_menu(self) -> None:
        # Меню пользователя
        while True:
            print(f"\n=== Меню ({self.user.username}) ===")
            print("1 — Показать пароли")
            print("2 — Добавить новый")
            print("3 — Удалить пароль")
            print("4 — Изменить мастер-пароль")
            print("h — Помощь")
            print("0 — Выйти в главное меню")
            choice = input("\n>>> ").strip().lower()
            if choice == "1":
                self._show_passwords()
            elif choice == "2":
                while True:
                    site = input("\nСервис: ").strip()
                    if site:
                        break
                    print(colored("\nИмя не может быть пустым.", "red"))
                if site in self.user.data and not self._ask_yes_no(
                    "Перезаписать? y/n: "
                ):
                    continue
                pwd = self._get_password()
                if pwd:
                    print(f"\nПароль: {pwd}\n")
                    if self._ask_yes_no("Сохранить? y/n: "):
                        self._save_password(site, pwd)
                        print("\n" + colored("✅ Сохранено.", "green"))
                        logging.info(
                            f"Пользователь {self.user.username} добавил пароль для {site}."
                        )
            elif choice == "3":
                if (
                    not self.user.data
                    or len(self.user.data) == 1
                    and "_test" in self.user.data
                ):
                    print(colored("\nПаролей нет.", "yellow"))
                    continue
                site = input("\nВведите сервис для удаления: ").strip()
                if site in self.user.data and site != "_test":
                    if self._ask_yes_no(f"Удалить пароль для {site}? y/n: "):
                        del self.user.data[site]
                        self.user.save_data()
                        print(colored("\n✅ Пароль удалён.", "green"))
                        logging.info(
                            f"Пользователь {self.user.username} удалил пароль для {site}."
                        )
                        if len(self.user.data) == 1 and "_test" in self.user.data:
                            if self._ask_yes_no(
                                f"\nВсе пароли удалены. Удалить пользователя {self.user.username}? y/n: "
                            ):
                                self.user.reset()
                                break
                else:
                    print(colored("\nСервис не найден.", "red"))
                    if self._ask_yes_no("\nСоздать? y/n: "):
                        pwd = self._get_password()
                        if pwd:
                            print(f"\nПароль: {pwd}\n")
                            if self._ask_yes_no("Сохранить? y/n: "):
                                self._save_password(site, pwd)
                                print("\n" + colored("✅ Сохранено.", "green"))
                                logging.info(
                                    f"Пользователь {self.user.username} добавил пароль для {site}."
                                )
            elif choice == "4":
                self.change_master_password()
            elif choice == "h":
                print("\nКраткий туториал:")
                print("1. Показать пароли: Отображает все сохранённые пароли.")
                print(
                    "2. Добавить новый: Добавляет пароль для сервиса (генерация или ручной ввод)."
                )
                print(
                    "3. Удалить пароль: Удаляет пароль для указанного сервиса; если не найден, предлагает создать."
                )
                print(
                    "4. Изменить мастер-пароль: Меняет мастер-пароль, перешифровывая данные."
                )
                print("0. Выйти: Возврат в главное меню.")
            elif choice == "0":
                if self._ask_yes_no("\nВыйти в главное меню? y/n: "):
                    logging.info(f"Пользователь {self.user.username} вышел из меню.")
                    break
            else:
                print(colored("Неверный выбор.", "red"))

    def run(self) -> None:
        # Запуск основного цикла программы
        print(colored("\nДобро пожаловать в Менеджер Паролей!", "green"))
        print("Краткий туториал:")
        print("1. Создайте пользователя и мастер-пароль для шифрования.")
        print("2. Войдите в аккаунт с мастер-паролем.")
        print("3. Добавляйте пароли для сервисов (генерируйте или вводите вручную).")
        print("4. Просматривайте, удаляйте или меняйте мастер-пароль.")
        print("Все данные хранятся локально и зашифрованы.\n")
        while True:
            print("\n=== Главное меню ===")
            print("1 — Войти")
            print("2 — Создать нового пользователя")
            print("0 — Выход")
            cmd = input("\n>>> ").strip()
            if cmd == "1":
                if self.login():
                    self.user_menu()
            elif cmd == "2":
                if self.create_user():
                    self.user_menu()
            elif cmd == "0":
                if self._ask_yes_no("Выйти из программы? y/n: "):
                    print(colored("Выход.", "yellow"))
                    logging.info("Программа завершена.")
                    break
            else:
                print(colored("Неверный выбор.", "red"))


if __name__ == "__main__":
    PasswordManager().run()
