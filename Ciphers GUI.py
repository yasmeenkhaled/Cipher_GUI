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

def generate_caesar_key(shift):
    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    shifted_alphabet = alphabet[shift:] + alphabet[:shift]
    return dict(zip(alphabet, shifted_alphabet))

def caesar_encrypt(plaintext, shift):
    key = generate_caesar_key(shift)
    return monoalphabetic_encrypt(plaintext, key)

def caesar_decrypt(ciphertext, shift):
    key = generate_caesar_key(shift)
    inverse_key = {v: k for k, v in key.items()}
    return monoalphabetic_encrypt(ciphertext, inverse_key)

def generate_playfair_key():
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 'J' is excluded
    shuffled_alphabet = random.sample(alphabet, len(alphabet))
    key = dict(zip(alphabet, shuffled_alphabet))
    return key

def prepare_playfair_input(text):
    text = text.upper().replace("J", "I")
    prepared_text = []
    for char in text:
        if char.isalpha():
            prepared_text.append(char)
    return "".join(prepared_text)

def playfair_encrypt(plaintext, key):
    prepared_text = prepare_playfair_input(plaintext)
    encrypted_text = ""
    for i in range(0, len(prepared_text), 2):
        pair = prepared_text[i:i+2]
        if len(pair) == 2 and pair[0] != pair[1]:
            row1, col1 = divmod(list(key.keys()).index(pair[0]), 5)
            row2, col2 = divmod(list(key.keys()).index(pair[1]), 5)
            if row1 == row2:
                encrypted_text += key[list(key.keys())[row1 * 5 + (col1 + 1) % 5]]
                encrypted_text += key[list(key.keys())[row2 * 5 + (col2 + 1) % 5]]
            elif col1 == col2:
                encrypted_text += key[list(key.keys())[(row1 + 1) % 5 * 5 + col1]]
                encrypted_text += key[list(key.keys())[(row2 + 1) % 5 * 5 + col2]]
            else:
                encrypted_text += key[list(key.keys())[row1 * 5 + col2]]
                encrypted_text += key[list(key.keys())[row2 * 5 + col1]]
        elif len(pair) == 1:
            encrypted_text += pair[0] + "X"
    return encrypted_text

def playfair_decrypt(ciphertext, key):
    inverse_key = {v: k for k, v in key.items()}
    return playfair_encrypt(ciphertext, inverse_key)

class ExtendedCipherGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Cipher GUI")

        self.monoalphabetic_key = generate_monoalphabetic_key()
        self.caesar_shift = 3  # Adjust as needed
        self.playfair_key = generate_playfair_key()

        self.setup_gui()

    def setup_gui(self):
        Label(self.master, text="Monoalphabetic Cipher").pack(pady=10)

        Label(self.master, text="Encryption:").pack()
        self.entry_mono_encrypt = Entry(self.master)
        self.entry_mono_encrypt.pack(pady=5)
        Button(self.master, text="Encrypt", command=self.perform_monoalphabetic_encryption).pack(pady=5)
        self.entry_mono_decrypt = Entry(self.master)
        self.entry_mono_decrypt.pack(pady=5)
        Button(self.master, text="Decrypt", command=self.perform_monoalphabetic_decryption).pack(pady=10)

        Label(self.master, text="Caesar Cipher:").pack()
        self.entry_caesar_encrypt = Entry(self.master)
        self.entry_caesar_encrypt.pack(pady=5)
        Button(self.master, text="Encrypt", command=self.perform_caesar_encryption).pack(pady=5)
        self.entry_caesar_decrypt = Entry(self.master)
        self.entry_caesar_decrypt.pack(pady=5)
        Button(self.master, text="Decrypt", command=self.perform_caesar_decryption).pack(pady=10)

        Label(self.master, text="Playfair Cipher:").pack()
        self.entry_playfair_encrypt = Entry(self.master)
        self.entry_playfair_encrypt.pack(pady=5)
        Button(self.master, text="Encrypt", command=self.perform_playfair_encryption).pack(pady=5)
        self.entry_playfair_decrypt = Entry(self.master)
        self.entry_playfair_decrypt.pack(pady=5)
        Button(self.master, text="Decrypt", command=self.perform_playfair_decryption).pack(pady=10)

    def perform_monoalphabetic_encryption(self):
        plaintext = self.entry_mono_encrypt.get()
        ciphertext = monoalphabetic_encrypt(plaintext, self.monoalphabetic_key)
        self.show_result("Encrypted Text (Monoalphabetic):", ciphertext)

    def perform_monoalphabetic_decryption(self):
        ciphertext = self.entry_mono_decrypt.get()
        plaintext = monoalphabetic_decrypt(ciphertext, self.monoalphabetic_key)
        self.show_result("Decrypted Text (Monoalphabetic):", plaintext)

    def perform_caesar_encryption(self):
        plaintext = self.entry_caesar_encrypt.get()
        ciphertext = caesar_encrypt(plaintext, self.caesar_shift)
        self.show_result("Encrypted Text (Caesar):", ciphertext)

    def perform_caesar_decryption(self):
        ciphertext = self.entry_caesar_decrypt.get()
        plaintext = caesar_decrypt(ciphertext, self.caesar_shift)
        self.show_result("Decrypted Text (Caesar):", plaintext)

    def perform_playfair_encryption(self):
        plaintext = self.entry_playfair_encrypt.get()
        ciphertext = playfair_encrypt(plaintext, self.playfair_key)
        self.show_result("Encrypted Text (Playfair):", ciphertext)

    def perform_playfair_decryption(self):
        ciphertext = self.entry_playfair_decrypt.get()
        plaintext = playfair_decrypt(ciphertext, self.playfair_key)
        self.show_result("Decrypted Text (Playfair):", plaintext)

    def show_result(self, label_text, result_text):
        result_var = StringVar()
        result_var.set(f"{label_text} {result_text}")
        Label(self.master, textvariable=result_var).pack()

if __name__ == "__main__":
    root = Tk()
    app = ExtendedCipherGUI(root)
    root.mainloop()
