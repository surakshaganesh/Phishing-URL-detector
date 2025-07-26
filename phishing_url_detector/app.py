from flask import Flask, request, render_template
import joblib
from extract_features import extract_features
import re
from datetime import datetime

app = Flask(__name__)

# Load your trained model
model = joblib.load("phishing_model.pkl")

# In-memory history list
history = []

# Function to validate URL
def is_valid_url(url):
    return re.match(r'^https?://[\w.-]+(?:\.[\w\.-]+)+[/\w\.-]*$', url)

@app.route('/', methods=['GET', 'POST'])
def index():
    prediction = None
    error = None

    if request.method == 'POST':
        url = request.form['url']
        if not url or not is_valid_url(url):
            error = "Please enter a valid URL (e.g., https://example.com)."
        else:
            features = extract_features(url)
            prediction = model.predict([features])[0]
            # Save to history
            history.append({
                'url': url,
                'result': prediction,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })

    return render_template('index.html', prediction=prediction, error=error, history=history)

if __name__ == '__main__':
    app.run(debug=True)
