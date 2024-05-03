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
from translations import _t, set_language, languages_list
from typing import Union

load_dotenv()


class PasswordManager:
    def __init__(self, page: ft.Page) -> None:
        set_language("pt_BR")

        self.page = page
        self.page.title = _t("Password Manager")
        self.page.window_center()
        self.page.window_height = 700
        self.page.window_width = 800

        self.app_data_path = appdirs.user_data_dir(appname="pManager")
        os.makedirs(self.app_data_path, exist_ok=True)
        self.user_data_path = os.path.join(self.app_data_path, "data.bin")

        self.password_list: list[tuple] = []

        # self.page.window_resizable = False
        self.master_user_pin = None
        self.master_key = None
        self.run()

    def theme_changed(self, e):
        if self.page.theme_mode == ft.ThemeMode.DARK:
            self.page.theme_mode = ft.ThemeMode.LIGHT
            self.bnt_theme.icon = ft.icons.DARK_MODE_OUTLINED
            self.bnt_theme.tooltip = "Modo Escuro"
        else:
            self.page.theme_mode = ft.ThemeMode.DARK
            self.bnt_theme.icon = ft.icons.LIGHT_MODE_OUTLINED
            self.bnt_theme.tooltip = "Modo Claro"

        self.page.update()

    def set_tema(self, tema):
        if tema.find("LIGHT") >= 0 and self.page.theme_mode == ft.ThemeMode.DARK:
            self.theme_changed(None)

        if tema.find("DARK") >= 0 and self.page.theme_mode == ft.ThemeMode.LIGHT:
            self.theme_changed(None)

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

    def verify_data(self, verification_type: int = 0) -> bool:
        # verification_type = 0 -> verifica se o arquivo existe
        # verification_type != 0 -> verifica apenas o token

        try:
            if verification_type == 0:
                if os.path.exists(
                    self.user_data_path
                ):  # Arquivo de dados existe, abre modal para inserir o Pin
                    self.input_pin_modal(None)

                else:  # Nao existe dados salvos, abre modal para criar pin
                    self.create_pin_modal(None)

            # Os modais inserem o valor no self.master_user_pin

            if self.master_user_pin:
                self.master_key = self.generate_key_from_pin(self.master_user_pin)
                data = self.load_encrypted_data()

                if data:
                    self.password_list = data
                    self.password_components()
                    return True

                else:
                    return False
        except:
            return False

    def encrypt_data(self, data):
        cipher_suite = Fernet(self.master_key)
        encrypted_data = cipher_suite.encrypt(json.dumps(data).encode())
        return encrypted_data

    def decrypt_data(self, encrypted_data):
        cipher_suite = Fernet(self.master_key)
        decrypted_data = json.loads(cipher_suite.decrypt(encrypted_data).decode())
        return decrypted_data

    def delete_data(self, e) -> None:
        if os.path.exists(self.user_data_path):
            os.remove(self.user_data_path)
            self.alert_modal(None, "Sucesso", "Dados Excluidos!")
        else:
            self.alert_modal(None, "Falha", "Não foi possivel excluir os dados.")

        self.verify_data()

    def save_encrypted_data(self):
        print(json.dumps(self.password_list, indent=2))
        encrypted_data = self.encrypt_data(self.password_list)
        # Converta os dados criptografados para base64
        encoded_data = base64.b64encode(encrypted_data)
        with open(self.user_data_path, "wb") as file:
            file.write(encoded_data)

    def load_encrypted_data(self) -> Union[tuple, bool]:
        try:
            with open(self.user_data_path, "rb") as file:
                # Decode de volta para bytes antes de decifrar
                encoded_data = base64.b64decode(file.read())
            decrypted_data = self.decrypt_data(encoded_data)
            decrypted_data = [tuple(sublist) for sublist in decrypted_data]
            # print(json.dumps(decrypted_data, indent=4))
            return decrypted_data

        except FileNotFoundError:
            print("Arquivo não encontrado.")
            return False

        except cryptography.fernet.InvalidToken:
            print("Token inválido")
            return False

        except Exception as e:
            print(f"Houve um problema ao carregar dados. {e}")
            return False

    def generate_random_password(self, length: int) -> None:
        characters = string.ascii_letters + string.digits + string.punctuation
        password = "".join(secrets.choice(characters) for _ in range(length))
        self.in_password_value.value = password
        self.in_password_value.update()

    def password_components(self) -> list[ft.Row]:
        def change_icon_color(e):
            print(1)
            e.control.icon_color = ft.colors.RED_400
            self.page.update()

        try:
            password_list: list[ft.Row] = []
            for name, password in self.password_list:
                password_list.append(
                    ft.Container(
                        ft.ResponsiveRow(
                            [
                                ft.TextField(
                                    value=name,
                                    border="none",
                                    col={"md": 6},
                                    read_only=True,
                                    height=40,
                                    text_vertical_align=-1,
                                ),
                                ft.Stack(
                                    [
                                        ft.Container(
                                            content=ft.TextField(
                                                password=True,
                                                can_reveal_password=True,
                                                border="none",
                                                value=password,
                                                read_only=True,
                                                multiline=False,
                                                height=40,
                                            ),
                                            margin=ft.margin.only(right=70),
                                        ),
                                        ft.IconButton(
                                            icon=ft.icons.CONTENT_COPY,
                                            icon_size=20,
                                            tooltip=_t("Copy"),
                                            data=password,
                                            on_click=self.copy_clipboard,
                                            right=35,
                                        ),
                                        ft.IconButton(
                                            on_focus=lambda e: print(e),
                                            icon=ft.icons.DELETE_FOREVER_ROUNDED,
                                            icon_size=20,
                                            tooltip=_t("Delete"),
                                            on_click=self.delete_password,
                                            data=name,
                                            right=5,
                                        ),
                                    ],
                                    col={"md": 6},
                                ),
                            ],
                            vertical_alignment=ft.MainAxisAlignment.CENTER,
                        ),
                        bgcolor=ft.colors.BLACK12,
                        # shadow=ft.BoxShadow(
                        #     spread_radius=0.01,
                        #     blur_radius=10,
                        #     color=ft.colors.BLACK38,
                        #     blur_style=ft.ShadowBlurStyle.NORMAL,
                        #     offset=ft.Offset(0, 5),
                        # ),
                        border_radius=10,
                        padding=5,
                        border=ft.border.all(1, ft.colors.BLACK),
                        height=50,
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
        self.save_encrypted_data()
        self.page.update()

    def add_password(self, e) -> None:
        try:
            name: str = self.in_password_name.value
            value: str = self.in_password_value.value

            self.in_password_name.value = None
            self.in_password_value.value = None

            if name and value:

                if not any(key == name for key, _password in self.password_list):
                    self.password_list.append((name, value))
                    self.password_components()
                else:
                    self.alert_modal(
                        None, _t("Error"), _t("The identifier provided already exists.")
                    )
                    raise ValueError("Identificador existente")

                self.save_encrypted_data()
            else:
                if not name:
                    self.in_password_name.error_text = "Campo obrigatório"

                if not name:
                    self.in_password_value.error_text = "Campo obrigatório"
                self.page.update()

        except Exception as e:
            print(e)

    def alert_modal(self, e, title: str, text: str):
        self.dlg_modal = ft.AlertDialog(
            title=ft.Text(title),
            content=ft.Text(text),
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: print("Modal dialog dismissed!"),
        )
        self.page.dialog = self.dlg_modal
        self.dlg_modal.open = True
        self.page.update()

    def clear_error(self, e):
        e.control.error_text = None
        self.page.update()

    def input_pin_modal(self, e) -> None:
        error_count = 0

        def set_pin(e):
            nonlocal error_count
            self.master_user_pin = in_pin.value
            if not self.verify_data(verification_type=1):
                in_pin.error_text = "Pin Inválido"

                if error_count > 2:
                    bnt_delete_data.disabled = False
                error_count += 1

            else:
                self.close_dlg(None)

            self.page.update()

        in_pin = ft.TextField(
            label=_t("Master key"),
            password=True,
            can_reveal_password=True,
            on_change=self.clear_error,
        )
        bnt_delete_data = ft.TextButton(
            "Apagar dados",
            on_click=self.confirm_delete_modal,
            disabled=True,
        )

        self.dlg_modal = ft.AlertDialog(
            modal=True,
            title=ft.Text(_t("Pin")),
            content=in_pin,
            actions=[
                bnt_delete_data,
                ft.TextButton("Ok", on_click=set_pin),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: print("Modal dialog dismissed!"),
        )
        self.page.dialog = self.dlg_modal
        self.dlg_modal.open = True
        self.page.update()

    def confirm_delete_modal(self, e) -> None:
        self.dlg_modal = ft.AlertDialog(
            title=ft.Text("Atenção"),
            content=ft.Text("Deseja prosseguir?"),
            actions=[
                ft.TextButton("Sim", on_click=self.delete_data),
                ft.TextButton("Não", on_click=self.close_dlg),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: print("Modal dialog dismissed!"),
        )
        self.page.dialog = self.dlg_modal
        self.dlg_modal.open = True
        self.page.update()

    def create_pin_modal(self, e) -> None:

        def verify_pin(e):
            if not in_new_pin.value:
                in_new_pin.error_text = "Campo obrigatório"

            elif not in_confirm_pin.value:
                in_confirm_pin.error_text = "Campo obrigatório"

            elif in_new_pin.value == in_confirm_pin.value:
                self.close_dlg(None)
                self.master_user_pin = in_new_pin.value
                self.verify_data(verification_type=1)

            else:
                in_new_pin.error_text = "Pins diferentes"
                in_confirm_pin.error_text = "Pins diferentes"

            self.page.update()

        in_new_pin = ft.TextField(
            label=_t("Master pin"),
            password=True,
            can_reveal_password=True,
            on_change=self.clear_error,
        )

        in_confirm_pin = ft.TextField(
            label=_t("Confirm pin"),
            password=True,
            can_reveal_password=True,
            on_change=self.clear_error,
        )
        self.dlg_modal = ft.AlertDialog(
            modal=True,
            title=ft.Text(_t("Create Pin")),
            content=ft.Column(controls=[in_new_pin, in_confirm_pin], height=120),
            actions=[
                ft.TextButton("Create", on_click=verify_pin),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: print("Modal dialog dismissed!"),
        )
        self.page.dialog = self.dlg_modal
        self.dlg_modal.open = True
        self.page.update()

    def close_dlg(self, e):
        self.dlg_modal.open = False
        self.page.update()

    def update_language(self, e):
        set_language(e.control.value)
        self.page.clean()
        self.place_components()

        # Refresh language dropdown text
        self.language_dropdown.value = e.control.value
        self.language_dropdown.update()

        # Refresh password list
        self.password_components()

    def place_components(self) -> None:
        try:
            self.language_dropdown = ft.Dropdown(
                options=[ft.dropdown.Option(language) for language in languages_list()],
                height=40,
                width=100,
                dense=True,
                autofocus=False,
                text_size=13,
                scale=0.8,
                on_change=self.update_language,
            )
            self.bnt_theme = ft.IconButton(
                icon=ft.icons.LIGHT_MODE_OUTLINED,
                icon_size=20,
                tooltip=_t("Light Mode"),
                on_click=self.theme_changed,
            )

            self.header = ft.Row(
                [
                    self.language_dropdown,
                    ft.Container(
                        content=ft.Text(
                            value=_t("Password Manager"),
                            size=20,
                            height=40,
                            weight=ft.FontWeight.W_800,
                        ),
                        alignment=ft.alignment.center,
                    ),
                    ft.Container(
                        content=(self.bnt_theme),
                        alignment=ft.alignment.center_right,
                    ),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            )

            self.out_passwords = ft.ListView(
                controls=[
                    ft.Row(
                        [ft.Text(value=_t("No password registered"))],
                        alignment=ft.MainAxisAlignment.CENTER,
                    )
                ],
                expand=1,
                spacing=10,
                padding=20,
                auto_scroll=True,
            )

            self.in_password_name = ft.TextField(
                label=_t("Identifier"),
                icon=ft.icons.ALTERNATE_EMAIL,
                hint_style=ft.TextStyle(size=11, italic=True),
                on_change=self.clear_error,
            )
            self.in_password_value = ft.TextField(
                label=_t("Password"),
                icon=ft.icons.ALTERNATE_EMAIL,
                hint_text=_t("Master Key"),
                hint_style=ft.TextStyle(size=11, italic=True),
                on_change=self.clear_error,
            )
            self.passwords_container = ft.Container(
                content=self.out_passwords,
                height=self.page.window_height - 300,
                border=ft.border.all(1, ft.colors.BLACK),
                border_radius=10,
                expand=True,
            )

            self.bnt_add_password = ft.ElevatedButton(
                text=_t("Add"), on_click=self.add_password
            )
            self.bnt_generate_random_password = ft.ElevatedButton(
                text=_t("Generate Random"),
                on_click=lambda e: self.generate_random_password(
                    int(self.password_size.value)
                ),
            )
            self.password_size = ft.Slider(
                min=8, max=128, divisions=15, label="{value}", width=300, value=8
            )

            self.out_botton_buttons = ft.Row(
                [
                    ft.Row(
                        [ft.Text(value=_t("Size")), self.password_size],
                    ),
                    self.bnt_generate_random_password,
                    self.bnt_add_password,
                ],
                alignment=ft.MainAxisAlignment.SPACE_EVENLY,
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

    def run(self) -> None:
        self.page.clean()
        self.place_components()
        self.verify_data()


if __name__ == "__main__":
    ft.app(target=PasswordManager)
