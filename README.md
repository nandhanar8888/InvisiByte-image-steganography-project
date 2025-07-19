InvisiByte – Image Steganography Tool

InvisiByte is a Python-based application that hides text or PDF files inside images using the Least Significant Bit (LSB) technique. It features a simple Tkinter GUI and password protection for secure, invisible data transmission.

Features:

Hide and extract text or PDF files within images

Uses LSB technique with minimal visual distortion

Password protection for added security

Simple Tkinter-based GUI

Save and retrieve encoded/decoded files easily

Project Structure:

bash
Copy
Edit
InvisiByte/
│
├── imagesteg.py               # Main Python script with encoding/decoding logic and GUI
├── stegno_log.txt             # Log file for tracking steganography operations
├── venv/                      # Virtual environment (not to be uploaded to GitHub)
└── .idea/                     # IDE settings (optional, can be added to .gitignore)
