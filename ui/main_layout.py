from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.label import Label
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .settings import SettingsPopup
from utils.encryption import encrypt_files, decrypt_files
from utils.encryption import prepare_key



class MainLayout(BoxLayout):
    def __init__(self, store, **kwargs):
        super(MainLayout, self).__init__(orientation='vertical', **kwargs)
        self.store = store

        self.file_chooser_encrypt = FileChooserListView()
        self.add_widget(self.file_chooser_encrypt)

        self.spinner = Spinner(
            text='Choose encryption method',
            values=('AES', 'DES'),
            size_hint=(None, None), size=(200, 44))
        self.add_widget(self.spinner)

        self.key_input = TextInput(hint_text='Enter encryption key', multiline=False)
        self.add_widget(self.key_input)

        self.encrypt_button = Button(text='Encrypt Files')
        self.encrypt_button.bind(on_press=self.encrypt_files)
        self.add_widget(self.encrypt_button)

        self.decrypt_button = Button(text='Decrypt Files')
        self.decrypt_button.bind(on_press=self.decrypt_files)
        self.add_widget(self.decrypt_button)

        settings_button = Button(text='Settings')
        settings_button.bind(on_press=self.show_settings)
        self.add_widget(settings_button)
        

    def show_settings(self, instance):
        popup = SettingsPopup(self.store)
        popup.open()

    def encrypt_files(self, instance):
        selected_files = self.file_chooser_encrypt.selection
        key = self.key_input.text
        delete_originals = self.store.get('delete_originals')['value'] if self.store.exists('delete_originals') else False
        encrypt_files(selected_files, key, self.spinner.text, self.show_popup, delete_originals)

    def decrypt_files(self, instance):
        selected_files = self.file_chooser_encrypt.selection
        key = self.key_input.text
        delete_after_decrypt = self.store.get('delete_after_decrypt')['value'] if self.store.exists('delete_after_decrypt') else False
        decrypt_files(selected_files, key, self.spinner.text, self.show_popup, delete_after_decrypt)

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(None, None), size=(400, 200))
        popup.open()
        print("Hello")