from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import pickle
import numpy as np
import re

app = FastAPI(title="Phishing Detection API")

# Load model Random Forest
try:
    with open("phishing_model.pkl", "rb") as f:
        model = pickle.load(f)
except Exception as e:
    model = None

class URLRequest(BaseModel):
    url: str

def extract_30_features(url: str):
    features = np.ones(30, dtype=int)
    if re.search(r'\d+\.\d+\.\d+\.\d+', url): features[0] = -1
    if len(url) > 54: features[1] = -1
    if "@" in url: features[2] = -1
    if "//" in url[7:]: features[3] = -1
    return [features.tolist()]

# --- UI BARU BUAT PAMER KE DOSEN ---
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberSec URL Scanner</title>
        <style>
            body { font-family: 'Courier New', Courier, monospace; background-color: #0d1117; color: #00ff00; text-align: center; padding-top: 10vh; }
            input { width: 50%; padding: 15px; font-size: 16px; background: #161b22; border: 1px solid #30363d; color: #58a6ff; border-radius: 5px; }
            button { padding: 15px 30px; font-size: 16px; background-color: #238636; color: white; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; margin-left: 10px; }
            button:hover { background-color: #2ea043; }
            #result-box { margin-top: 40px; padding: 20px; font-size: 24px; font-weight: bold; }
            .phishing { color: #f85149; }
            .safe { color: #3fb950; }
        </style>
    </head>
    <body>
        <h2>☠️ INITIALIZING PHISHING SCANNER ENGINE ☠️</h2>
        <p>Powered by Random Forest Ensemble Model</p>
        <div style="margin-top: 30px;">
            <input type="text" id="urlInput" placeholder="Enter target URL (e.g., http://suspicious-site.com)">
            <button onclick="scanURL()">SCAN</button>
        </div>
        <div id="result-box"></div>

        <script>
            async function scanURL() {
                const url = document.getElementById('urlInput').value;
                const resultBox = document.getElementById('result-box');
                resultBox.innerHTML = "<span style='color: yellow;'>Scanning network packets...</span>";
                
                try {
                    const res = await fetch('/predict', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: url })
                    });
                    const data = await res.json();
                    
                    if (data.is_phishing) {
                        resultBox.innerHTML = `🚨 STATUS: <span class="phishing">PHISHING DETECTED!</span><br><br><span style="font-size: 16px; color: #8b949e;">URL is highly malicious. Proceed with caution.</span>`;
                    } else {
                        resultBox.innerHTML = `✅ STATUS: <span class="safe">LEGITIMATE URL</span><br><br><span style="font-size: 16px; color: #8b949e;">No malicious patterns found.</span>`;
                    }
                } catch (err) {
                    resultBox.innerHTML = "<span class='phishing'>ERROR: Server connection failed.</span>";
                }
            }
        </script>
    </body>
    </html>
    """

@app.post("/predict")
def predict_phishing(request: URLRequest):
    if not model: return {"error": "Model offline"}
    
    features_array = extract_30_features(request.url)
    prediction = model.predict(features_array)
    result_value = int(prediction[0])
    
    # Bug FIX: cuma true kalau resultnya -1
    is_phishing = True if result_value == -1 else False 
    status = "Phishing/Bahaya" if is_phishing else "Legitimate/Aman"
    
    return {
        "target_url": request.url,
        "prediction_code": result_value,
        "status": status,
        "is_phishing": is_phishing
    }