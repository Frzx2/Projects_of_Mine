from kivy.app import App
from kivy.uix.button import Button
import os
from kivy.uix.screenmanager import ScreenManager, Screen, FadeTransition, SwapTransition, SlideTransition, \
    WipeTransition
from cryptography.fernet import Fernet
from kivy.core.window import Window
import json
import hashlib
import secrets
import base64
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.core.clipboard import Clipboard
from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.boxlayout import MDBoxLayout


class Login(MDScreen):
    def login(self):
        password = self.ids.passb.text
        if not password:
            self.ids.label02.text = "Invaild Password Try agian."
            return

        try:
            with open("master.key", "r") as f:
                data = json.load(f)
                salt = base64.b64decode(data["salt"])
                stored_key = base64.b64decode(data["key"])

            entered_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

            if entered_key == stored_key:
                self.ids.label02.text = "Login Successful"
                Clock.schedule_once(self.go_to_main, 0.1)
                if  not os.path.exists("secret.key") or os.path.getsize("secret.key") == 0:
                        key = Fernet.generate_key()
                        with open("secret.key", "wb") as key_file:
                            key_file.write(key)
            else:
                self.ids.label02.text = "Incorrect Password"
                self.ids.passb.text = ""

        except Exception as e:
            self.ids.label02.text = f"Error: {str(e)}"
    def go_to_main(self, dt):
        if self.manager:
            self.manager.current = "manage"
        else:
            pass
class View_password(MDScreen):
    def on_enter(self):
        self.load_passwords()
        self.manager.current = "view"
    def load_passwords(self, filter_text=""):
        self.ids.password_grid.clear_widgets()

        if not os.path.exists("data.json") or os.path.getsize("data.json") == 0:
            data = {}
        else:
            with open("data.json", "r") as f:
                data = json.load(f)
        # Load encryption key
        with open("secret.key", "rb") as f:
            key = f.read()

        fernet = Fernet(key)

        for site, info in data.items():
            if filter_text.lower() not in site.lower():
                continue
            website = site
            enc_pass = info["password"]
            username = info["username"]

            from kivymd.uix.button import MDRaisedButton

            btn = MDRaisedButton(
                text=site,
                size_hint_y=1,
                height="48dp",
                md_bg_color=(0.1, 0.5, 0.8, 1),
                text_color=(1, 1, 1, 1),
                pos_hint={"center_x": 0.5},
                on_release=lambda btn_instance, s=username, p=enc_pass: self.expand_password(
                    btn_instance, s, p, fernet, website
                )
            )

            self.ids.password_grid.add_widget(btn)

    def expand_password(self, button, site, enc_pass, fernet, website):
        try:
            decrypted_pass = fernet.decrypt(enc_pass.encode()).decode()
        except Exception:
            decrypted_pass = "[Decryption Error]"

        layout = MDBoxLayout(
            orientation='horizontal',
            size_hint_x=1,
            size_hint_y=None,
            height='50dp',
            spacing=10,
            padding=(10, 0)
        )

        layout.add_widget(
            MDRaisedButton(
                text=f"Username: {site}\nPassword: {decrypted_pass}",
                size_hint_x=3,
                md_bg_color=(0.2, 0.6, 0.9, 1),
                text_color=(1, 1, 1, 1)
            )
        )

        layout.add_widget(
            MDRaisedButton(
                text="Copy Username",
                size_hint_x=1.5,
                md_bg_color=(0.2, 0.7, 0.4, 1),
                text_color=(1, 1, 1, 1),
                on_release=lambda x: Clipboard.copy(site)
            )
        )

        layout.add_widget(
            MDRaisedButton(
                text="Copy Password",
                size_hint_x=1.5,
                md_bg_color=(0.1, 0.5, 0.9, 1),
                text_color=(1, 1, 1, 1),
                on_release=lambda x: Clipboard.copy(decrypted_pass)
            )
        )

        layout.add_widget(
            MDRaisedButton(
                text="Delete",
                size_hint_x=1.2,
                md_bg_color=(0.9, 0.2, 0.2, 1),
                text_color=(1, 1, 1, 1),
                on_release=lambda x: self.delete_password(website)
            )
        )

        layout.add_widget(
            MDRaisedButton(
                text="Edit",
                size_hint_x=1.2,
                md_bg_color=(1, 0.6, 0, 1),
                text_color=(1, 1, 1, 1),
                on_release=lambda x: self.edit_password(site, decrypted_pass, website)
            )
        )

        self.ids.password_grid.remove_widget(button)
        self.ids.password_grid.add_widget(layout)
    def delete_password(self, site):
        if os.path.exists("data.json"):
            with open("data.json", "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}
            if site in data:
                del data[site]
                with open("data.json", "w") as f:
                    json.dump(data, f, indent=4)
                self.load_passwords(self.ids.search_bar.text)
    def filter_passwords(self,text):
        self.load_passwords(filter_text=text)
    def edit_password(self,site,decrypted_pass,website):
        self.manager.get_screen("edit_password").edit(site,decrypted_pass,website)
        self.manager.current = "edit_password"
class Insert_password(MDScreen):
    def back(self):
        self.manager.current = "manage"
    def add_password(self):
        self.manager.current = "insert"
    def save_password(self):
        web_name = self.ids.web_name.text
        web_user_name = self.ids.user_name.text
        web_pass = self.ids.web_pass.text
        if not web_pass or not web_name or not web_user_name:
            if not web_name:
                self.ids.label03.text = "Input A vaild web Name"
            elif not web_pass:
                self.ids.label03.text = "Input A vaild web Pass"
            elif not web_user_name:
                self.ids.label03.text = "Input A vaild User Name"
            else:
                self.ids.label03.text = "Input A vaild form"
        else:
            if not os.path.exists("secret.key"):
                key = Fernet.generate_key()
                with open("secret.key", "wb") as key_file:
                    key_file.write(key)
            else:
                with open("secret.key", "rb") as key_file:
                    key = key_file.read()
            fernet = Fernet(key)
            encrypted_pass = fernet.encrypt(web_pass.encode()).decode()
            if os.path.exists("data.json"):
                with open("data.json", "r") as f:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError:
                        data = {}
            else:
                data = {}

            data[web_name] = {
                "username":web_user_name,
                "password":encrypted_pass
            }

            # Save updated data back to file
            with open("data.json", "w") as f:
                json.dump(data, f, indent=4)

            # UI feedback
            self.ids.label03.text = "Password saved securely!"
            self.ids.web_name.text = ""
            self.ids.web_pass.text = ""
            self.ids.user_name.text = ""
class Create_password(MDScreen):
    def create(self):
        password = self.ids.new_pass.text
        if not password:
            return
        salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        data = {
            "salt":base64.b64encode(salt).decode(),
            "key":base64.b64encode(key).decode()
        }
        with open("master.key", "w") as f:
            json.dump(data, f)
        self.ids.label01.text = "Password Created Successfully"
        Clock.schedule_once(self.gotologin, 0.1)
    def gotologin(self,dt):
        self.manager.current = "login"
class manage_password(MDScreen):
    pass
class edit_password(MDScreen):
    def edit(self,site,decrypted_pass,website):
        self.ids.website.text  = website
        self.ids.username.text = site
        self.ids.password.text = decrypted_pass
        self.website_selected = website
    def updatepass(self):
        web = self.ids.website.text
        name = self.ids.username.text
        password = self.ids.password.text
        if not password or not name or not web:
            if not name:
                self.ids.label04.text = "Input A vaild web Name"
            elif not password:
                self.ids.label04.text = "Input A vaild web Pass"
            elif not web:
                self.ids.label04.text = "Input A vaild User Name"
            else:
                self.ids.label04.text = "Input A vaild form"
        else:
            with open("data.json", "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}
                if self.website_selected in data:
                    del data[self.website_selected]

                    with open("secret.key", "rb") as key_file:
                        key = key_file.read()
                    fernet = Fernet(key)
                    encrypted_pass = fernet.encrypt(password.encode()).decode()
                    data[web] = {
                        "username": name,
                        "password": encrypted_pass
                    }
                    with open("data.json","w") as f:
                        json.dump(data,f,indent=4)
                else:
                    pass
            self.manager.current = "view"
    def back(self):
        self.manager.current = 'view'
class main(MDApp):
    def build(self):
        sm = ScreenManager(transition=WipeTransition())
        sm.add_widget(Login(name="login"))
        sm.add_widget(View_password(name="view"))
        sm.add_widget(Insert_password(name="insert"))
        sm.add_widget(Create_password(name="create"))
        sm.add_widget(manage_password(name="manage"))
        self.theme_cls.primary_palette = "Blue"
        sm.add_widget(edit_password(name = "edit_password"))
        if os.path.exists("master.key"):
            if os.path.getsize("master.key") == 0:
                sm.current = "create"
            else:
                sm.current = "login"
        else:
            sm.current = "create"
        return sm
if __name__ == "__main__":
    main().run()
