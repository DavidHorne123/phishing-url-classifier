import pandas as pd
import re
import tldextract
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
import numpy as np

# Load dataset
df = pd.read_csv("C:/Users/David Horne/PycharmProjects/pythonphishing_url_classifier/PhishingdataSet/archive/malicious_phish.csv")

# Clean and prepare
df = df.dropna().drop_duplicates()
df = df[df['type'].isin(['phishing', 'benign'])]
df = df.rename(columns={'type': 'label'})
df['label'] = df['label'].map({'phishing': 1, 'benign': 0})

# Feature extraction
def extract_features(url):
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

# Extract features
features = pd.DataFrame([extract_features(url) for url in df['url']])
features['label'] = df['label'].values

# Encode TLDs
le = LabelEncoder()
features['tld'] = le.fit_transform(features['tld'])

# Convert to smaller dtypes to reduce model memory
X = features.drop(columns=['label']).astype({
    'url_length': 'int16',
    'has_https': 'int8',
    'num_dots': 'int8',
    'has_at': 'int8',
    'has_hyphen': 'int8',
    'num_digits': 'int8',
    'uses_ip': 'int8',
    'tld': 'int16'
})
y = features['label'].astype('int8')

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train smaller model
clf = RandomForestClassifier(n_estimators=30, max_depth=8, random_state=42)
clf.fit(X_train, y_train)

# Save compressed model and encoder
joblib.dump(clf, "phishing_model.pkl", compress=9, protocol=4)
joblib.dump(le, "tld_encoder.pkl", compress=9, protocol=4)

print("✅ Compressed model and encoder saved successfully.")
