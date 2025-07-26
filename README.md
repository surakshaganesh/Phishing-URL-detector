# Phishing URL Detector 🔍

This is a mini project built using **Flask**, which detects whether a given URL is **Phishing** or **Legitimate** using a trained Machine Learning model (Random Forest).


## 🚀 Features

- 🔍 Predicts if a URL is **Phishing** or **Legitimate** using a trained **Random Forest Classifier**.
- ✅ Green checkmark for Legitimate, ⚠️ Red warning for Phishing.
- 🛑 URL validation to avoid invalid inputs.
- 🧾 Maintains a history log of scanned URLs with timestamps.
- 🧠 Feature-based detection using manually engineered URL features.

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
3. Activate the environment for windows:
    .venv\Scripts\activate
4. Install dependencies:
    pip install -r requirements.txt
5. run the app:
    python app.py

## Future Enhancements
 - Add real-time crawling and domain WHOIS features.
 - Improve model with deep learning.
 - Host on Render or Vercel.
