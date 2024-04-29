import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import flet as ft
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import base64
import json
import pyperclip
import threading
import appdirs
import secrets
import string

load_dotenv()


class PasswordManager:
    def __init__(self, page):
        self.page = page
        self.password_list: list[tuple] = []
        self.page.title = "Password Manager"
        self.page.window_center()
        self.page.window_height = 700
        self.page.window_width = 800
        self.app_data_path = appdirs.user_data_dir(appname="pManager")
        os.makedirs(self.app_data_path, exist_ok=True)
        self.user_data_path = os.path.join(self.app_data_path, "data.bin")
        # self.page.window_resizable = False
        self.run()
        self.verify_data()

    def generate_key_from_pin(self, pin: str) -> bytes:
        pin_bytes = pin.encode()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"salt_value",
            iterations=100000,
            backend=default_backend(),
        )

        key = kdf.derive(pin_bytes)

        return base64.urlsafe_b64encode(key)

    def verify_data(self):
        self.master_key = self.generate_key_from_pin("122")

        print(self.app_data_path)

        status, data = self.load_encrypted_data()
        if status:
            self.password_list = data
            self.password_components()
        else:
            print(data)
            ## Modal de Aviso

    def encrypt_data(self, data):
        cipher_suite = Fernet(self.master_key)
        encrypted_data = cipher_suite.encrypt(json.dumps(data).encode())
        return encrypted_data

    def decrypt_data(self, encrypted_data):
        cipher_suite = Fernet(self.master_key)
        decrypted_data = json.loads(cipher_suite.decrypt(encrypted_data).decode())
        return decrypted_data

    def save_encrypted_data(self):
        print(json.dumps(self.password_list, indent=2))
        encrypted_data = self.encrypt_data(self.password_list)
        # Converta os dados criptografados para base64
        encoded_data = base64.b64encode(encrypted_data)
        with open(self.user_data_path, "wb") as file:
            file.write(encoded_data)

    def load_encrypted_data(self) -> tuple:
        try:
            with open(self.user_data_path, "rb") as file:
                # Decode de volta para bytes antes de decifrar
                encoded_data = base64.b64decode(file.read())
            decrypted_data = self.decrypt_data(encoded_data)
            decrypted_data = [tuple(sublist) for sublist in decrypted_data]
            # print(json.dumps(decrypted_data, indent=4))
            return True, decrypted_data

        except FileNotFoundError:
            return False, "Arquivo não encontrado."
        except cryptography.fernet.InvalidToken:
            return False, f"Token inválido"
        except Exception as e:
            return False, f"Houve um problema ao carregar dados. {e}"

    def generate_random_password(self, length: int) -> None:
        characters = string.ascii_letters + string.digits + string.punctuation
        password = "".join(secrets.choice(characters) for _ in range(length))
        self.in_password_value.value = password
        self.in_password_value.update()

    def password_components(self) -> list[ft.Row]:
        try:
            password_list: list[ft.Row] = []
            for name, password in self.password_list:
                password_list.append(
                    ft.Row(
                        [
                            ft.TextField(value=name),
                            ft.Row(
                                [
                                    ft.TextField(
                                        password=True,
                                        can_reveal_password=True,
                                        border="none",
                                        value=password,
                                    ),
                                    ft.IconButton(
                                        icon=ft.icons.CONTENT_COPY,
                                        icon_size=20,
                                        tooltip="Copy",
                                        data=password,
                                        on_click=self.copy_clipboard,
                                    ),
                                    ft.IconButton(
                                        icon=ft.icons.DELETE_FOREVER_ROUNDED,
                                        icon_size=20,
                                        tooltip="Delete",
                                        on_click=self.delete_password,
                                        data=name,
                                    ),
                                ]
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    )
                )

            self.out_passwords.controls = password_list
            self.page.update()

        except Exception as e:
            print(e)

    def copy_clipboard(self, e) -> None:
        pyperclip.copy(e.control.data)
        e.control.icon_color = ft.colors.GREEN
        e.control.icon = ft.icons.CHECK
        self.page.update()
        threading.Timer(5.0, self.reset_icon_color, args=(e.control,)).start()

    def reset_icon_color(self, control):
        control.icon_color = None
        control.icon = ft.icons.CONTENT_COPY
        self.page.update()

    def delete_password(self, e) -> None:
        for chave, valor in self.password_list:
            if chave == e.control.data:
                self.password_list.remove((chave, valor))
                break

        self.password_components()
        self.page.update()

    def add_password(self, e) -> None:
        try:
            name: str = self.in_password_name.value
            value: str = self.in_password_value.value

            if name and value:

                if not any(key == name for key, _password in self.password_list):
                    self.password_list.append((name, value))
                    self.password_components()
                else:
                    # self.open_dlg(None)
                    self.alert_modal(
                        None, "Falha", "O identificador informado já existe."
                    )
                    raise ValueError("Identificador existente")
                self.save_encrypted_data()
        except Exception as e:
            print(e)

    def alert_modal(self, e, title: str, text: str):
        dlg_modal = ft.AlertDialog(
            title=ft.Text(title),
            content=ft.Text(text),
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: print("Modal dialog dismissed!"),
        )
        self.page.dialog = dlg_modal
        dlg_modal.open = True
        self.page.update()

    def close_dlg(self, e):
        self.dlg_modal.open = False
        self.page.update()

    def open_dlg(self, e):
        self.page.dialog = self.dlg_modal
        self.dlg_modal.open = True
        self.page.update()

    def place_components(self) -> None:
        try:
            self.header = ft.Row(
                [
                    ft.Container(),
                    ft.Container(
                        content=ft.Text(
                            value="Password Manager",
                            size=20,
                            height=40,
                            weight=ft.FontWeight.W_800,
                        ),
                        alignment=ft.alignment.center,
                    ),
                    ft.Container(
                        content=(
                            bnt_tema := ft.IconButton(
                                icon=ft.icons.LIGHT_MODE_OUTLINED,
                                icon_size=20,
                                tooltip="Modo Claro",
                            )
                        ),
                        alignment=ft.alignment.center_right,
                    ),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            )

            self.out_passwords = ft.ListView(
                controls=[
                    ft.Row(
                        [ft.Text(value="Nenhuma senha registrada")],
                        alignment=ft.MainAxisAlignment.CENTER,
                    )
                ],
                expand=1,
                spacing=10,
                padding=20,
                auto_scroll=True,
            )

            self.in_password_name = ft.TextField(
                label="Identifier",
                icon=ft.icons.ALTERNATE_EMAIL,
                hint_style=ft.TextStyle(size=11, italic=True),
            )
            self.in_password_value = ft.TextField(
                label="Password Key",
                icon=ft.icons.ALTERNATE_EMAIL,
                hint_text="Master Key",
                hint_style=ft.TextStyle(size=11, italic=True),
            )
            self.passwords_container = ft.Container(
                content=self.out_passwords,
                height=self.page.window_height - 300,
                border=ft.border.all(1, ft.colors.BLACK),
                border_radius=10,
            )

            self.bnt_add_password = ft.ElevatedButton(
                text="Add", on_click=self.add_password
            )
            self.bnt_generate_random_password = ft.ElevatedButton(
                text="Generate Random",
                on_click=lambda e: self.generate_random_password(10),
            )
            self.out_botton_buttons = ft.Row(
                [self.bnt_generate_random_password, self.bnt_add_password]
            )

            self.page.add(
                self.header,
                self.passwords_container,
                self.in_password_name,
                self.in_password_value,
                self.out_botton_buttons,
            )

        except Exception as e:
            print(e)

    def run(self):

        self.place_components()


if __name__ == "__main__":
    ft.app(target=PasswordManager)
