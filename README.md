# Phishing URL Detector 🔍

This is a mini project built using **Flask**, which detects whether a given URL is **Phishing** or **Legitimate** using a trained Machine Learning model (Random Forest).

## 💡 Features
- Flask-based web interface
- URL input form with validation
- Real-time predictions with icons (✅ / ⚠️)
- History log with timestamp
- Trained ML model using 48 features

## 🖥️ Tech Stack
- Python, Flask
- Scikit-learn
- HTML, CSS
- Joblib, Regex

## ⚙️ How to Run

1. Clone this repository  
2. Create a virtual environment:
   ```bash
    python -m venv venv
3. Activate the environment:
    Windows: venv\Scripts\activate
4. Install dependencies:
    pip install -r requirements.txt
5. run the app:
    python app.py

## Future Enhancements
 - Add real-time crawling and domain WHOIS features.
 - Improve model with deep learning.
 - Host on Render or Vercel.