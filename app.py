import streamlit as st
import time
import numpy as np
import pandas as pd
import random
import re
from urllib.parse import urlparse
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier

# -------------------------------------------------
# PAGE CONFIG
# -------------------------------------------------

st.set_page_config(page_title="Cybersecurity URL Detection", layout="wide")

# -------------------------------------------------
# SESSION STATE
# -------------------------------------------------

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# -------------------------------------------------
# LOGIN PAGE
# -------------------------------------------------

def login_page():
    st.title("🔐 Cybersecurity Login Portal")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "csdavanthi2026":
            st.success("Login Successful!")
            time.sleep(1)
            st.session_state.logged_in = True
            st.rerun()
        else:
            st.error("Invalid Credentials")

# -------------------------------------------------
# FEATURE EXTRACTION
# -------------------------------------------------

def is_valid_url(url):
    pattern = re.compile(
        r'^(https?:\/\/)?'
        r'([a-zA-Z0-9-]+\.)+'
        r'[a-zA-Z]{2,}'
        r'(\/.*)?$'
    )
    return re.match(pattern, url) is not None


def extract_features(url):

    parsed = urlparse(url)
    if not parsed.netloc:
        url = "http://" + url
        parsed = urlparse(url)

    domain = parsed.netloc
    path = parsed.path

    features = []

    features.append(len(url))
    features.append(len(domain))
    features.append(len(path))
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('@'))
    features.append(url.count('?'))
    features.append(url.count('%'))
    features.append(url.count('='))

    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)

    features.append(digits)
    features.append(letters)
    features.append(digits / (letters + 1))

    features.append(1 if parsed.scheme == "https" else 0)
    features.append(1 if parsed.scheme == "http" else 0)

    ip_pattern = r'\d+\.\d+\.\d+\.\d+'
    features.append(1 if re.search(ip_pattern, url) else 0)

    phishing_keywords = ["login","verify","secure","update","bank","account"]
    features.append(1 if any(word in url.lower() for word in phishing_keywords) else 0)

    adult_keywords = ["porn","xxx","sex","adult","nude"]
    features.append(1 if any(word in url.lower() for word in adult_keywords) else 0)

    features.append(domain.count('.'))
    features.append(1 if '-' in domain else 0)

    tld = domain.split('.')[-1] if '.' in domain else ""
    features.append(len(tld))

    features.append(1 if '.' not in domain else 0)

    return features

# -------------------------------------------------
# MODEL TRAINING (Cached)
# -------------------------------------------------

@st.cache_resource
def train_models():

    legit_domains = ["google.com", "amazon.com", "microsoft.com", "github.com"]
    phish_keywords = ["login", "verify", "secure", "update", "bank"]
    adult_domains = ["xxxvideos.com", "freepornhub.xxx", "adultsite.sex"]

    data = []

    for _ in range(3000):
        r = random.random()

        if r < 0.33:
            url = "https://www." + random.choice(legit_domains)
            label = 0
        elif r < 0.66:
            keyword = random.choice(phish_keywords)
            url = "http://" + keyword + "-secure-" + str(random.randint(100,999)) + ".com"
            label = 1
        else:
            url = "http://" + random.choice(adult_domains)
            label = 1

        data.append([url, label])

    df = pd.DataFrame(data, columns=["url","label"])

    X = []
    y = df["label"].values

    for url in df["url"]:
        X.append(extract_features(url))

    X = np.array(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Decision Tree": DecisionTreeClassifier(),
        "Random Forest": RandomForestClassifier(),
        "SVM": SVC(probability=True),
        "KNN": KNeighborsClassifier()
    }

    results = {}
    trained_models = {}

    for name, model in models.items():
        model.fit(X_train, y_train)
        predictions = model.predict(X_test)
        acc = accuracy_score(y_test, predictions)
        results[name] = acc
        trained_models[name] = model

    return trained_models, results

# -------------------------------------------------
# MAIN DASHBOARD
# -------------------------------------------------

def main_dashboard():

    # Background style
    st.markdown("""
        <style>
        .stApp {
            background: linear-gradient(to right, #0f2027, #203a43, #2c5364);
            color: white;
        }
        </style>
    """, unsafe_allow_html=True)

    # Logo
    st.image("assets/logo.png", width=150)

    st.title("🔐 AI Powered Cybersecurity URL Detection")

    trained_models, results = train_models()

    url_input = st.text_input("Enter URL to Analyze")

    if st.button("Analyze URL"):

        if not is_valid_url(url_input):
            st.error("⚠️ Invalid URL format! Marked as MALICIOUS ❌")
        else:

            with st.spinner("Analyzing URL..."):
                time.sleep(2)

            features = np.array(extract_features(url_input)).reshape(1, -1)

            predictions = []
            confidences = []

            for name, model in trained_models.items():
                pred = model.predict(features)[0]
                prob = model.predict_proba(features)[0]
                confidence = max(prob) * 100

                label = "MALICIOUS ❌" if pred == 1 else "LEGITIMATE ✅"
                predictions.append((name, label, confidence))
                confidences.append(confidence)

            st.subheader("Model Predictions")

            for name, label, conf in predictions:
                st.write(f"**{name}** → {label} | Confidence: {conf:.2f}% | Accuracy: {results[name]*100:.2f}%")

            votes = [1 if p[1] == "MALICIOUS ❌" else 0 for p in predictions]
            final_decision = "MALICIOUS ❌" if sum(votes) > len(votes)/2 else "LEGITIMATE ✅"

            st.subheader("Final Majority Decision")
            st.success(final_decision)

            fig, ax = plt.subplots()
            ax.bar([p[0] for p in predictions], confidences)
            ax.set_ylabel("Confidence (%)")
            plt.xticks(rotation=45)

            st.pyplot(fig)

# -------------------------------------------------
# ROUTING
# -------------------------------------------------

if not st.session_state.logged_in:
    login_page()
else:
    main_dashboard()
