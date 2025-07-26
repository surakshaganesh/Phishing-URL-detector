import joblib
from phishing_url_detector.extract_features import extract_features
import pandas as pd

# Load the trained model
model = joblib.load("phishing_model.pkl")

# Get the URL to check
url = input("Enter the URL to check: ").strip()

features = extract_features(url)
print("Extracted feature count:", len(features))
for name, value in zip(model.feature_names_in_, features):
    print(f"{name}: {value}")


# Ensure feature names match training dataset
feature_names = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
    'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
    'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
    'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
    'DomainInSubdomains', 'DomainInPaths', 'HttpsInHostname',
    'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath',
    'NumSensitiveWords', 'EmbeddedBrandName', 'PctExtHyperlinks',
    'PctExtResourceUrls', 'ExtFavicon', 'InsecureForms',
    'RelativeFormAction', 'ExtFormAction', 'AbnormalFormAction',
    'PctNullSelfRedirectHyperlinks', 'FrequentDomainNameMismatch',
    'FakeLinkInStatusBar', 'RightClickDisabled', 'PopUpWindow',
    'SubmitInfoToEmail', 'IframeOrFrame', 'MissingTitle',
    'ImagesOnlyInForm', 'SubdomainLevelRT', 'UrlLengthRT',
    'PctExtResourceUrlsRT', 'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT',
    'PctExtNullSelfRedirectHyperlinksRT'
]

# Convert features to DataFrame
features_df = pd.DataFrame([features], columns=feature_names)

# Make prediction
prediction = model.predict(features_df)[0]
print("Prediction Output:", prediction)

# Show result
if prediction == 1:
    print("❌ Phishing Website")
else:
    print("✅ Legitimate Website")
