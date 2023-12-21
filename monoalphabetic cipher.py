import random
from tkinter import *

def generate_monoalphabetic_key():
    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    shuffled_alphabet = alphabet.copy()
    random.shuffle(shuffled_alphabet)
    return dict(zip(alphabet, shuffled_alphabet))

def monoalphabetic_encrypt(plaintext, key):
    encrypted_text = ""
    for char in plaintext:
        if char.isalpha():
            encrypted_text += key[char.upper()]
        else:
            encrypted_text += char
    return encrypted_text

def monoalphabetic_decrypt(ciphertext, key):
    inverse_key = {v: k for k, v in key.items()}
    return monoalphabetic_encrypt(ciphertext, inverse_key)

class MonoalphabeticGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Monoalphabetic Cipher")

        self.key = generate_monoalphabetic_key()

        self.setup_gui()

    def setup_gui(self):
        Label(self.master, text="Monoalphabetic Cipher").pack(pady=10)

        Label(self.master, text="Encryption:").pack()
        self.entry_encrypt = Entry(self.master)
        self.entry_encrypt.pack(pady=5)
        Button(self.master, text="Encrypt", command=self.perform_encryption).pack(pady=10)

        Label(self.master, text="Decryption:").pack()
        self.entry_decrypt = Entry(self.master)
        self.entry_decrypt.pack(pady=5)
        Button(self.master, text="Decrypt", command=self.perform_decryption).pack(pady=10)

    def perform_encryption(self):
        plaintext = self.entry_encrypt.get()
        ciphertext = monoalphabetic_encrypt(plaintext, self.key)
        self.show_result("Encrypted Text:", ciphertext)

    def perform_decryption(self):
        ciphertext = self.entry_decrypt.get()
        plaintext = monoalphabetic_decrypt(ciphertext, self.key)
        self.show_result("Decrypted Text:", plaintext)

    def show_result(self, label_text, result_text):
        result_var = StringVar()
        result_var.set(f"{label_text} {result_text}")
        Label(self.master, textvariable=result_var).pack()

if __name__ == "__main__":
    root = Tk()
    app = MonoalphabeticGUI(root)
    root.mainloop()
