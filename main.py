# phishing_url_classifier.py


import pandas as pd  # for handling tabular data
import re  # for regex pattern matching
import tldextract  # to extract domain and suffix from URLs
from urllib.parse import urlparse  # to parse URLs into components
from sklearn.ensemble import RandomForestClassifier  # the machine learning model
from sklearn.model_selection import train_test_split  # to split data into training and test sets
from sklearn.preprocessing import LabelEncoder  # to convert categorical data into numbers
from sklearn.metrics import classification_report  # to evaluate model performance
import numpy as np


# Load dataset from Kaggle CSV
# Update with full path to CSV file
# Ensure this matches the actual location of the file on your machine
df = pd.read_csv("C:/Users/David Horne/PycharmProjects/pythonphishing_url_classifier/PhishingdataSet/archive/malicious_phish.csv")
print("Dataset shape:", df.shape)


# Rename columns for consistency (if needed)
df = df.rename(columns={'url': 'url', 'type': 'label'})


# Convert label from text to binary: phishing = 1, benign = 0
df['label'] = df['label'].map({'phishing': 1, 'benign': 0})


# Drop rows where label mapping failed
df = df.dropna(subset=['label'])
df = df.reset_index(drop=True)  # Reset index to align labels and features correctly


# Clean the dataset (optional but recommended)
df = df.drop_duplicates()


# Show cleaned dataset info
print("Cleaned dataset shape:", df.shape)
print("Label distribution:\n", df['label'].value_counts())


# Function to extract lexical features from a given URL
def extract_features(url):
   parsed = urlparse(url)
   ext = tldextract.extract(url)
   features = {
       'url_length': len(url),
       'has_https': int(url.startswith("https")),
       'num_dots': url.count('.'),
       'has_at': int('@' in url),
       'has_hyphen': int('-' in url),
       'num_digits': sum(c.isdigit() for c in url),
       'uses_ip': int(bool(re.match(r'https?://\d+\.\d+\.\d+\.\d+', url))),
       'tld': ext.suffix
   }
   return features


# Apply the feature extraction function to each URL in the dataset
df_features = pd.DataFrame([extract_features(url) for url in df['url']])
df_features['label'] = df['label']
df_features = df_features.dropna(subset=['label'])
df_features['label'] = df_features['label'].astype(int)
print("Feature set shape:", df_features.shape)


# Convert categorical TLD (top-level domain) feature into numeric codes
le = LabelEncoder()
df_features['tld'] = le.fit_transform(df_features['tld'])


# Split the dataset into features (X) and labels (y)
X = df_features.drop(columns=['label'])
y = df_features['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
print("Train set size:", X_train.shape)
print("Test set size:", X_test.shape)


# Train the model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))


# --- USER URL CHECKING ---
known_safe_domains = ['google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com']


while True:
   user_input = input("\nEnter a URL to check (or type 'exit' to quit): ")
   if user_input.lower() == 'exit':
       break


   domain = tldextract.extract(user_input)
   full_domain = f"{domain.domain}.{domain.suffix}"


   if full_domain in known_safe_domains:
       print("🟢 Safe (Trusted Domain — Whitelisted)")
       continue


   input_features = extract_features(user_input)


   try:
       input_features['tld'] = le.transform([input_features['tld']])[0]
   except:
       print("Unknown TLD — this URL was not seen in training. Assigning default value.")
       input_features['tld'] = np.median(df_features['tld'])  # use median TLD code instead of -1


   input_df = pd.DataFrame([input_features])
   prediction = clf.predict(input_df)[0]
   label = "🔴 Suspicious (Phishing)" if prediction == 1 else "🟢 Safe"
   print(f"Prediction: {label}")

