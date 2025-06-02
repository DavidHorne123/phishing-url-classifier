import pandas as pd
import re
import tldextract
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib

# Load dataset
df = pd.read_csv("C:/Users/David Horne/Desktop/PhishingdataSet/archive/malicious_phish.csv")

# Clean and prepare
df = df.dropna()
df = df.drop_duplicates()
df = df[df['type'].isin(['phishing', 'benign'])]
df = df.rename(columns={'url': 'url', 'type': 'label'})
df['label'] = df['label'].map({'phishing': 1, 'benign': 0})
df = df.dropna(subset=['label'])  # Remove rows with missing labels

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

# Extract features and labels
features = pd.DataFrame([extract_features(url) for url in df['url']])
features['label'] = df['label'].values

# Encode TLDs
le = LabelEncoder()
features['tld'] = le.fit_transform(features['tld'])

# Split data
X = features.drop(columns=['label'])
y = features['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Save model and encoder
joblib.dump(clf, "phishing_model.pkl")
joblib.dump(le, "tld_encoder.pkl")

print("✅ Model and encoder saved successfully.")
