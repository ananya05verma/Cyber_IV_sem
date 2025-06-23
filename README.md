# 🛡️ PhishShield

PhishShield is a machine learning–powered phishing detection system integrated with a Chrome browser extension. It helps protect users from phishing websites by analyzing URLs and providing real-time alerts for malicious sites.

---

## 🚀 Features

- 🔍 Detects phishing URLs using a trained Random Forest classifier
- 🧠 Model trained on lexical features from URL datasets
- 🌐 Chrome extension for real-time URL monitoring
- 🛑 Warns users before they visit malicious websites
- 📦 Flask backend API to communicate between model and browser

---

## 🗂️ Project Structure
phishshield/
│
├── app.py # Flask backend server
├── Model/
│ ├── data.csv # Dataset used for training
│ ├── model.ipynb # Model training notebook
│ ├── model.pkl # Saved model
│ ├── Pipeline.joblib # Preprocessing + model pipeline
│ └── test.py # Test script for model
│
└── phishaway-extension1/
├── background.js # Extension background script
├── manifest.json # Chrome extension config
└── warning.html # Warning page for blocked URLs

---

## 🧠 How It Works

1. **Model Training**
   - A Random Forest classifier is trained on a dataset of URLs (`data.csv`) based on lexical features (length, use of symbols, domain, etc.).
   - The model is serialized using `joblib` and served via a Flask API.

2. **Chrome Extension**
   - Monitors active URLs visited by the user.
   - Sends the URL to the Flask backend.
   - Receives the prediction (phishing or not).
   - Redirects to a custom warning page if the site is detected as malicious.

---

## 🛠️ Setup Instructions

### Backend (Flask + ML Model)

```bash
# Step 1: Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Step 2: Install dependencies
pip install flask pandas scikit-learn joblib

# Step 3: Run the Flask app
python app.py
