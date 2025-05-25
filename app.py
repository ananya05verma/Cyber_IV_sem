from flask import Flask, request, jsonify
import requests
import base64
import logging
from flask_cors import CORS
import joblib
import pandas as pd

app = Flask(__name__)
CORS(app)

API_KEY = '0d4ccf231c9c49666f4e3e6bebf37cc6cd129e2617a7dce462c3f04f49c1f73a' 

logging.basicConfig(level=logging.DEBUG)

# Load Random Forest model and pipeline
try:
    model = joblib.load("Model/model.pkl")
    pipeline = joblib.load("Model/Pipeline.joblib")
    logging.info("Random Forest model and pipeline loaded.")
except Exception as e:
    logging.error(f"Error loading model or pipeline: {e}")
    model = None
    pipeline = None

def get_url_id(url):
    url_bytes = url.encode()
    b64_url = base64.urlsafe_b64encode(url_bytes).decode().strip("=")
    return b64_url

def check_url_virustotal(url):
    headers = {
        "x-apikey": API_KEY
    }
    url_id = get_url_id(url)
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    response = requests.get(vt_url, headers=headers)

    if response.status_code != 200:
        logging.error(f"VirusTotal API error: {response.status_code} {response.text}")
        return None

    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]

    logging.debug(f"VirusTotal stats: {stats}")

    if stats["malicious"] > 0 or stats["suspicious"] > 0:
        return "malicious"
    return "legitimate"

def check_url_ml(url):
    if model is None or pipeline is None:
        return "unknown"

    try:
        df = pd.DataFrame({"url": [url]})
        features = pipeline.transform(df)
        prediction = model.predict(features)[0]
        return "malicious" if prediction == 1 else "legitimate"
    except Exception as e:
        logging.error(f"ML prediction failed: {e}")
        return "error"

@app.route('/check_url', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        url = data.get("url", "")
        if not url:
            return jsonify({"error": "URL missing"}), 400

        result = check_url_virustotal(url)

        # Fallback to ML if VirusTotal fails
        if result is None:
            logging.info("VirusTotal failed. Using Random Forest fallback.")
            result = check_url_ml(url)

        return jsonify({"result": result})
    except Exception as e:
        logging.exception("Exception in /check_url")
        return jsonify({"result": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)



#	http://hdfcbank-login-alert.info/security-update
#   http://paypal.login-update-secure.verify-info.com
#   http://login-microsoft.support-update-security.ru
#   http://secure-facebook-account-recovery-login.in
#   http://appleid.apple.com-account-check.verification.io
#   http://google.login.auth.verify-now-security.com
#   http://bankofamerica.verify-identity-check-login.com
#   http://secure.netflix.account-confirmation-update.ru
#   http://amazon.login.payment-update-security-check.net
#   http://dropbox.com-user.verify-authenticate-system.cc
#   http://bit.ly/secure-login-paypal-info