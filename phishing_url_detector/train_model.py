import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# Load dataset
df = pd.read_csv("Phishing_Legitimate_full.csv")
print(df['CLASS_LABEL'].value_counts())

# Ensure correct columns
if 'CLASS_LABEL' not in df.columns:
    raise ValueError("❌ The dataset must contain 'CLASS_LABEL' column.")

# Split features and labels
X = df.drop(columns=['CLASS_LABEL', 'id'])  # Drop 'id' if it exists
y = df['CLASS_LABEL']

# Split into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# Save model
joblib.dump(model, 'phishing_model.pkl')
print("✅ Model trained and saved successfully.")

# Evaluate model
y_pred = model.predict(X_test)
print("\n📊 Model Evaluation Report:")
print(classification_report(y_test, y_pred))
