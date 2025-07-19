from tkinter import *
import tkinter.filedialog
from tkinter import simpledialog
from tkinter import messagebox
from PIL import ImageTk, Image
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import re


class IMG_Stegno:
    def __init__(self):
        self.cipher_suite = None
        self.root = None
        self.colors = {
            'bg': '#F0F4F8',
            'button': '#5B6E94',
            'button_hover': '#404E6B',
            'text': '#2D3748',
            'accent': '#9F7AEA'
        }

    def validate_password(self, password):
        """
                Validates if the password meets the requirements:
                - At least 8 characters
                - Contains both letters and numbers
                - Special characters allowed
                """
        if not password or len(password) < 8:
            return False, "Password must be at least 8 characters long"

        if not any(c.isalpha() for c in password):
            return False, "Password must contain at least one letter"

        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"

        return True, "Password is valid"

    def get_valid_password(self, prompt):
        """
        Repeatedly prompts for a password until a valid one is entered or canceled
        """
        while True:
            password = simpledialog.askstring("Password", prompt, show='*')
            if password is None:  # User clicked Cancel
                return None

            is_valid, message = self.validate_password(password)
            if is_valid:
                return password
            else:
                messagebox.showerror("Invalid Password", message)

    def generate_key(self, password):
        salt = b'\x00' * 16
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher_suite = Fernet(key)

    def main(self, root):
        self.root = root
        root.title('Image Steganography with PDF Support')
        root.geometry('800x900')
        root.resizable(width=True, height=True)
        root.minsize(600, 700)
        root.config(bg=self.colors['bg'])

        main_container = Frame(root, bg=self.colors['bg'])
        main_container.pack(expand=True, fill=BOTH, padx=20, pady=20)

        title_frame = Frame(main_container, bg=self.colors['bg'])
        title_frame.pack(fill=X, pady=(20, 40))

        icon_label = Label(title_frame, text='🔒', bg=self.colors['bg'], fg=self.colors['text'],
                           font=('Arial', 60))
        icon_label.pack()

        title = Label(title_frame, text='InvisiByte', bg=self.colors['bg'],
                      fg=self.colors['text'])
        title.config(font=('Comic Sans MS', 45, 'bold'))
        title.pack()

        subtitle = Label(title_frame, text='Secure PDF Hiding Tool', bg=self.colors['bg'],
                         fg=self.colors['accent'])
        subtitle.config(font=('Helvetica', 18, 'italic'))
        subtitle.pack(pady=(10, 0))

        self.button_style = {
            'font': ('Helvetica', 20),
            'bg': self.colors['button'],
            'fg': 'white',
            'activebackground': self.colors['button_hover'],
            'activeforeground': 'white',
            'padx': 40,
            'pady': 15,
            'bd': 0,
            'relief': 'flat',
            'cursor': 'hand2',
        }

        button_frame = Frame(main_container, bg=self.colors['bg'])
        button_frame.pack(expand=True, fill=BOTH, pady=30)

        encode_frame = Frame(button_frame, bg=self.colors['bg'])
        encode_frame.pack(expand=True, pady=15)

        encode_icon = Label(encode_frame, text='📁', bg=self.colors['bg'], fg=self.colors['text'],
                            font=('Arial', 30))
        encode_icon.pack()

        encode = Button(encode_frame, text="Encode PDF",
                        command=lambda: self.encode_frame1(main_container), **self.button_style)
        encode.pack(pady=10)

        decode_frame = Frame(button_frame, bg=self.colors['bg'])
        decode_frame.pack(expand=True, pady=15)

        decode_icon = Label(decode_frame, text='🔍', bg=self.colors['bg'], fg=self.colors['text'],
                            font=('Arial', 30))
        decode_icon.pack()

        decode = Button(decode_frame, text="Decode PDF",
                        command=lambda: self.decode_frame1(main_container), **self.button_style)
        decode.pack(pady=10)

    def back(self, frame):
        frame.destroy()
        self.main(self.root)

    def encode_frame1(self, F):
        F.destroy()
        main_container = Frame(self.root, bg=self.colors['bg'])
        main_container.pack(expand=True, fill=BOTH, padx=20, pady=20)

        icon_label = Label(main_container, text='📄', bg=self.colors['bg'], fg=self.colors['text'],
                           font=('Arial', 60))
        icon_label.pack(pady=(20, 10))

        label1 = Label(main_container, text='Select the Image to hide PDF:', bg=self.colors['bg'],
                       fg=self.colors['text'])
        label1.config(font=('Times New Roman', 35, 'bold'))
        label1.pack(pady=(10, 30))

        button_frame = Frame(main_container, bg=self.colors['bg'])
        button_frame.pack(expand=True, pady=20)

        button_bws = Button(button_frame, text='Select',
                            command=lambda: self.encode_frame2(main_container),
                            **self.button_style)
        button_bws.pack(pady=10)

        button_back = Button(button_frame, text='Go Back',
                             command=lambda: self.back(main_container),
                             **self.button_style)
        button_back.pack(pady=10)

    def decode_frame1(self, F):
        F.destroy()
        main_container = Frame(self.root, bg=self.colors['bg'])
        main_container.pack(expand=True, fill=BOTH, padx=20, pady=20)

        icon_label = Label(main_container, text='🔍', bg=self.colors['bg'], fg=self.colors['text'],
                           font=('Arial', 60))
        icon_label.pack(pady=(20, 10))

        label1 = Label(main_container, text='Select Image with Hidden PDF:', bg=self.colors['bg'],
                       fg=self.colors['text'])
        label1.config(font=('Times New Roman', 35, 'bold'))
        label1.pack(pady=(10, 30))

        button_frame = Frame(main_container, bg=self.colors['bg'])
        button_frame.pack(expand=True, pady=20)

        button_bws = Button(button_frame, text='Select',
                            command=lambda: self.decode_frame2(main_container),
                            **self.button_style)
        button_bws.pack(pady=10)

        button_back = Button(button_frame, text='Go Back',
                             command=lambda: self.back(main_container),
                             **self.button_style)
        button_back.pack(pady=10)

    def encode_frame2(self, e_F2):
        myfile = tkinter.filedialog.askopenfilename(
            filetypes=[('Image Files', '*.png;*.jpg;*.jpeg'), ('All Files', '*.*')])
        if not myfile:
            messagebox.showerror("Error", "No image selected!")
        else:
            pdf_file = tkinter.filedialog.askopenfilename(filetypes=[('PDF Files', '*.pdf')])
            if not pdf_file:
                messagebox.showerror("Error", "No PDF selected!")
            else:
                password = self.get_valid_password("Enter an alphanumeric password (min 8 characters):")
                if password is None:
                    return

                self.generate_key(password)

                my_img = Image.open(myfile)
                window_width = self.root.winfo_width()
                window_height = self.root.winfo_height()
                preview_width = min(400, int(window_width * 0.5))
                preview_height = min(300, int(window_height * 0.4))
                new_image = my_img.resize((preview_width, preview_height))
                img = ImageTk.PhotoImage(new_image)

                e_F2.destroy()
                main_container = Frame(self.root, bg=self.colors['bg'])
                main_container.pack(expand=True, fill=BOTH, padx=20, pady=20)

                icon_label = Label(main_container, text='🖼️', bg=self.colors['bg'],
                                   fg=self.colors['text'], font=('Arial', 50))
                icon_label.pack(pady=(10, 0))

                label3 = Label(main_container, text='Selected Image', bg=self.colors['bg'],
                               fg=self.colors['text'])
                label3.config(font=('Helvetica', 25, 'bold'))
                label3.pack(pady=(5, 20))

                img_frame = Frame(main_container, bg=self.colors['button'], padx=3, pady=3)
                img_frame.pack()
                panel = Label(img_frame, image=img)
                panel.image = img
                panel.pack()

                button_frame = Frame(main_container, bg=self.colors['bg'])
                button_frame.pack(expand=True, pady=40)

                button_enc = Button(button_frame, text='Encode PDF',
                                    command=lambda: self.enc_pdf(my_img, pdf_file),
                                    **self.button_style)
                button_enc.pack(pady=10)

                button_back = Button(button_frame, text='Go Back',
                                     command=lambda: self.back(main_container),
                                     **self.button_style)
                button_back.pack(pady=10)

    def enc_pdf(self, img, file_path):
        print("Encoding PDF...")

        with open(file_path, 'rb') as f:
            binary_file_data = f.read()
        print(f"Read {len(binary_file_data)} bytes from PDF file.")

        encrypted_data = self.cipher_suite.encrypt(binary_file_data)
        print(f"Encrypted data length: {len(encrypted_data)} bytes.")

        binary_data = ''.join(format(byte, '08b') for byte in encrypted_data)
        binary_data += '1111111111111110'
        print(f"Binary data length: {len(binary_data)} bits.")

        max_bits = img.width * img.height * 3
        if len(binary_data) > max_bits:
            raise ValueError("PDF file is too large for the image")

        encoded_img = img.copy()
        data = iter(encoded_img.getdata())

        for i in range(0, len(binary_data), 3):
            try:
                r, g, b = next(data)
                r = (r & ~1) | int(binary_data[i]) if i < len(binary_data) else r
                g = (g & ~1) | int(binary_data[i + 1]) if i + 1 < len(binary_data) else g
                b = (b & ~1) | int(binary_data[i + 2]) if i + 2 < len(binary_data) else b
                encoded_img.putpixel((i // 3 % img.width, i // 3 // img.width), (r, g, b))
            except StopIteration:
                print("Not enough pixels to encode all data.")
                break

        save_path = tkinter.filedialog.asksaveasfilename(defaultextension=".png", filetypes=[('PNG Files', '*.png')])
        if save_path:
            encoded_img.save(save_path)
            messagebox.showinfo("Success", f"Image successfully encoded and saved as {save_path}")
        else:
            messagebox.showerror("Error", "No save path selected!")

    def decode_frame2(self, d_F2):
        myfile = tkinter.filedialog.askopenfilename(
            filetypes=[('Image Files', '*.png;*.jpg;*.jpeg'), ('All Files', '*.*')])
        if not myfile:
            messagebox.showerror("Error", "No image selected!")
        else:
            password = self.get_valid_password("Enter your alphanumeric password:")
            if password is None:
                return

            self.generate_key(password)

            my_img = Image.open(myfile)
            extracted_file = self.dec_pdf(my_img)
            if extracted_file:
                save_path = tkinter.filedialog.asksaveasfilename(defaultextension=".pdf",
                                                                 filetypes=[('PDF Files', '*.pdf')])
                if save_path:
                    with open(save_path, 'wb') as f:
                        f.write(extracted_file)
                    messagebox.showinfo("Success", f"PDF successfully decoded and saved as {save_path}")
                else:
                    messagebox.showerror("Error", "No save path selected!")

    def dec_pdf(self, img):
        print("Decoding PDF...")
        binary_data = ''
        data = iter(img.getdata())

        while True:
            try:
                r, g, b = next(data)
                binary_data += f'{r & 1}{g & 1}{b & 1}'
            except StopIteration:
                break

        all_bytes = [binary_data[i:i + 8] for i in range(0, len(binary_data), 8)]

        decrypted_data = bytearray()
        for byte in all_bytes:
            if byte == '11111110':
                break
            decrypted_data.append(int(byte, 2))

        try:
            decrypted_data = self.cipher_suite.decrypt(bytes(decrypted_data))
            return decrypted_data
        except Exception as e:
            messagebox.showerror("Error", "Incorrect password or corrupted data!")
            return None


root = Tk()
o = IMG_Stegno()
o.main(root)
root.mainloop()
