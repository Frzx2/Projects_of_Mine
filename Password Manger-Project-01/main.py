from kivy.app import App
from kivy.uix.button import Button
import os
from kivy.uix.screenmanager import ScreenManager, Screen
from cryptography.fernet import Fernet
import json
import hashlib
import secrets
import base64
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.core.clipboard import Clipboard



class Login(Screen):
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
                Clock.schedule_once(self.go_to_main, 0.5)
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
class View_password(Screen):
    def on_enter(self):
        self.load_passwords()
        self.manager.current = "view"
    def load_passwords(self, filter_text=""):
        self.ids.password_grid.clear_widgets()

        if not os.path.exists("data.json"):
            return

        with open("data.json", "r") as f:
            data = json.load(f)

        # Load encryption key
        with open("secret.key", "rb") as f:
            key = f.read()

        fernet = Fernet(key)

        for site, enc_pass in data.items():
            if filter_text.lower() not in site.lower():
                continue

            btn = Button(
                text=site,
                size_hint_y=None,
                height='40dp',
                background_color =(0,0,0,0.5),
                on_release=lambda btn_instance, s=site, p=enc_pass: self.expand_password(btn_instance, s, p, fernet)
            )
            self.ids.password_grid.add_widget(btn)

    def expand_password(self, button, site, enc_pass, fernet):
        try:
            decrypted_pass = fernet.decrypt(enc_pass.encode()).decode()
        except Exception:
            decrypted_pass = "[Decryption Error]"

        layout = BoxLayout(orientation='horizontal', size_hint_y=None, height='40dp', spacing=10)

        layout.add_widget(Button(
            text=f" Webstite: {site} \n Password: {decrypted_pass}",
            size_hint_x=0.5,
            on_release=lambda x: None,
            background_color = (0,0,0,0.5)
        ))

        layout.add_widget(Button(
            text="Copy",
            size_hint_x=0.25,
            on_release=lambda x: Clipboard.copy(decrypted_pass),
            background_color = (0,0,0,0.5)
        ))

        layout.add_widget(Button(
            text="Delete",
            size_hint_x=0.25,
            background_color=(0,0,0,0.5),
            on_release=lambda x: self.delete_password(site)
        ))

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

class Insert_password(Screen):
    def back(self):
        self.manager.current = "manage"
    def add_password(self):
        self.manager.current = "insert"
    def save_password(self):
        web_name = self.ids.web_name.text
        web_pass = self.ids.web_pass.text
        if not web_pass or not web_name:
            if not web_name:
                self.ids.label03.text = "Input A vaild web Name"
            elif not web_pass:
                self.ids.label03.text = "Input A vaild web Pass"
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

            # Update the data with new password
            data[web_name] = encrypted_pass

            # Save updated data back to file
            with open("data.json", "w") as f:
                json.dump(data, f, indent=4)

            # UI feedback
            self.ids.label03.text = "Password saved securely!"
            self.ids.web_name.text = ""
            self.ids.web_pass.text = ""
class Create_password(Screen):
    def create(self):
        password = self.ids.new_pass.text
        if not password:
            print("Password cannot be empty")
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
        Clock.schedule_once(self.gotologin, 0.5)
    def gotologin(self,dt):
        self.manager.current = "login"


class main(App):
    def build(self):
        sm = ScreenManager()
        sm.add_widget(Login(name="login"))
        sm.add_widget(View_password(name="view"))
        sm.add_widget(Insert_password(name="insert"))
        sm.add_widget(Create_password(name="create"))
        if os.path.exists("master.key"):
            sm.current = "login"
        else:
            sm.current = "create"
        return sm
if __name__ == "__main__":
    main().run()