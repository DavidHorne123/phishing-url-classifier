import pandas as pd
import re
import tldextract
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import numpy as np
import tkinter as tk
from tkinter import messagebox, scrolledtext

# Load model and encoder
try:
    clf = joblib.load("phishing_model.pkl")
except FileNotFoundError:
    messagebox.showerror("Model Error", "phishing_model.pkl not found. Please train and save the model first.")
    exit()
try:
    le = joblib.load("tld_encoder.pkl")
except FileNotFoundError:
    messagebox.showerror("Encoder Error", "tld_encoder.pkl not found. Please train and save the encoder first.")
    exit()

# Feature extraction

def extract_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    return {
        'url_length': len(url),
        'has_https': int(url.startswith("https")),
        'num_dots': url.count('.'),
        'has_at': int('@' in url),
        'has_hyphen': int('-' in url),
        'num_digits': sum(c.isdigit() for c in url),
        'uses_ip': int(bool(re.match(r'https?://\d+\.\d+\.\d+\.\d+', url))),
        'tld': ext.suffix
    }

# Safe domain whitelist
known_safe_domains = ['google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com']

# GUI function
# Function to check whether a URL is safe or suspicious
def check_url():
    user_input = url_entry.get()  # Get the URL entered by the user
    if not user_input:
        messagebox.showwarning("Input Error", "Please enter a URL.")  # Show warning if input is empty
        return

    # Extract domain and suffix (e.g., 'example.com') using tldextract
    domain = tldextract.extract(user_input)
    full_domain = f"{domain.domain}.{domain.suffix}"

    # Check if the domain is in the whitelist of known safe domains
    if full_domain in known_safe_domains:
        result = "🟢 Safe (Trusted Domain — Whitelisted)"  # Trusted, known domain
    else:
        # Extract features from the URL (e.g., length, special characters, etc.)
        input_features = extract_features(user_input)

        # Attempt to encode the top-level domain (TLD) using the pre-fitted LabelEncoder
        try:
            input_features['tld'] = le.transform([input_features['tld']])[0]
        except:
            # If the TLD is unknown, assign a fallback value (median of existing TLD encodings)
            input_features['tld'] = int(np.median(le.transform(le.classes_)))

        # Convert features into a DataFrame for model prediction
        input_df = pd.DataFrame([input_features])

        # Make prediction using the trained model (1 = phishing, 0 = safe)
        prediction = clf.predict(input_df)[0]
        result = "🔴 Suspicious (Phishing)" if prediction == 1 else "🟢 Safe"

    # Display the result to the user
    result_var.set(f"Prediction: {result}")

    # Append the result to the history box
    history_box.insert(tk.END, f"{user_input} → {result}\n")
    history_box.see(tk.END)  # Scroll to the latest entry


# Function to clear the input field, result label, and history box
def clear_fields():
    url_entry.delete(0, tk.END)  # Clear the URL entry field
    result_var.set("")  # Clear the result display
    history_box.delete(1.0, tk.END)  # Clear the history log


# ---------------- GUI SETUP ----------------

# Create the main application window
root = tk.Tk()
root.title("URL Phishing Checker")  # Title of the window
root.geometry("500x400")  # Set fixed window size
root.resizable(False, False)  # Disable window resizing

# URL input label
url_label = tk.Label(root, text="Enter a URL:", font=("Arial", 12))
url_label.pack(pady=(15, 5))

# URL input entry field
url_entry = tk.Entry(root, width=60, font=("Arial", 10))
url_entry.pack(pady=5)

# Frame to hold the Check and Clear buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

# Button to check if the URL is phishing or safe
check_button = tk.Button(button_frame, text="Check URL", command=check_url, width=15)
check_button.pack(side=tk.LEFT, padx=5)

# Button to clear all fields
clear_button = tk.Button(button_frame, text="Clear", command=clear_fields, width=15)
clear_button.pack(side=tk.LEFT, padx=5)

# Label to show the result (Safe or Suspicious)
result_var = tk.StringVar()
result_label = tk.Label(root, textvariable=result_var, font=("Arial", 14), fg="blue")
result_label.pack(pady=10)

# Label for the history section
history_label = tk.Label(root, text="History:", font=("Arial", 11, "bold"))
history_label.pack(pady=(10, 0))

# Scrollable text box to display past URL checks
history_box = scrolledtext.ScrolledText(root, height=8, width=60, font=("Courier", 10))
history_box.pack(pady=5)

# Start the Tkinter event loop
root.mainloop()
