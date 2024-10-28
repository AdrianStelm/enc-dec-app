import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature



def encrypt_files(selected_files, key, method, show_popup, delete_originals):
    if not selected_files:
        show_popup("Error", "No file selected!")
        return

    if not key:
        show_popup("Error", "Please enter a key!")
        return

    if method == 'AES':
        key = prepare_key(key, length=32)
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend()).encryptor()
    else:
        key = prepare_key(key, length=8)
        iv = os.urandom(8)
        encryptor = Cipher(algorithms.DES(key), modes.CFB(iv), backend=default_backend()).encryptor()

    for file_path in selected_files:
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Генеруємо HMAC для контролю правильності дешифрування
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(ciphertext)
        hmac_digest = h.finalize()

        # Додаємо спеціальний заголовок "ENCRYPTED" для зашифрованого файлу
        # header = b"ENCRYPTED"

        # Створюємо зашифрований файл
        new_file_path = f"{file_path}.enc"
        with open(new_file_path, 'wb') as f:
            f.write(header + iv + ciphertext + hmac_digest)

        show_popup("Success", f"Files successfully encrypted! Saved as {new_file_path}")

        if delete_originals:
            os.remove(file_path)


def decrypt_files(selected_files, key, method, show_popup, delete_after_decrypt):
    if not selected_files:
        show_popup("Error", "No file selected!")
        return

    if not key:
        show_popup("Error", "Please enter a key!")
        return

    if method == 'AES':
        key = prepare_key(key, length=32)
        block_size = 16
    else:
        key = prepare_key(key, length=8)
        block_size = 8

    for file_path in selected_files:
        try:
            # Відкриваємо зашифрований файл для читання
            with open(file_path, 'rb') as f:
                header = f.read(9)

                if header != b"ENCRYPTED":
                    show_popup("Error", "This file is not encrypted!")
                    return

                iv = f.read(block_size)
                ciphertext = f.read()
                hmac_digest = ciphertext[-32:]
                ciphertext = ciphertext[:-32]

                # Верифікуємо HMAC
                h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
                h.update(ciphertext)
                try:
                    h.verify(hmac_digest)
                except InvalidSignature:
                    show_popup("Error", "File may be corrupted or key is incorrect.")
                    return

                # Розшифровуємо файл
                decryptor = Cipher(
                    algorithms.AES(key) if method == 'AES' else algorithms.DES(key),
                    modes.CFB(iv), 
                    backend=default_backend()
                ).decryptor()

                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Створюємо шлях для збереження розшифрованого файлу
            new_file_path = file_path[:-4]
            with open(new_file_path, 'wb') as f:
                f.write(plaintext)

            show_popup("Success", f"File successfully decrypted! Saved as {new_file_path}")

            # Перевірка на видалення зашифрованого файлу
            if delete_after_decrypt:
                os.remove(file_path)  # Видаляємо файл лише після його закриття

        except Exception as e:
            show_popup("Error", f"Failed to decrypt {file_path}. Error: {e}")

def prepare_key(key, length):
    # Форматування ключа
    return key.ljust(length)[:length].encode('utf-8')
