import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# Step 1: Load the dataset
df = pd.read_csv('Phishing_Legitimate_full.csv')

# Step 2: Explore and clean
print("Shape of dataset:", df.shape)
print("First 5 rows:\n", df.head())

# Optional: If there are unnamed index columns, drop them
df.drop(columns=[col for col in df.columns if "Unnamed" in col], inplace=True)

# Step 3: Features and labels
X = df.drop('CLASS_LABEL', axis=1)  # Features
y = df['CLASS_LABEL']               # Labels (0 = Legit, 1 = Phishing)

# Step 4: Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 5: Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Step 6: Predict and evaluate
y_pred = model.predict(X_test)
print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Step 7: Save model
joblib.dump(model, 'phishing_model.pkl')
print("\n✅ Model saved as phishing_model.pkl")
