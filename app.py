from typing import List
from urllib.parse import urlparse

import pickle
import re
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, HttpUrl

app = FastAPI(
    title="Phishing Detection API",
    description="Multi-modal phishing detection using an XGBoost URL model and live HTML page analysis.",
    version="1.0.0",
)

MODEL_PATH = "phishing_model.pkl"
DEEP_SCAN_TIMEOUT = 6
BRAND_KEYWORDS = {
    "paypal",
    "microsoft",
    "google",
    "facebook",
    "apple",
    "amazon",
    "netflix",
    "bank",
    "appleid",
    "login",
}
SPECIAL_CHARACTERS = set("!$^*()[]{}|<>#%\"';:,/\\`~")

model = None
model_classes = None
model_status = "unavailable"

try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    model_classes = getattr(model, "classes_", None)
    model_status = MODEL_PATH
except FileNotFoundError:
    model_status = "missing_model_file"
except Exception as exc:
    model_status = f"model_load_error: {exc}"


class URLRequest(BaseModel):
    url: HttpUrl = Field(..., description="Target URL to analyze for phishing risk")


class PredictionResult(BaseModel):
    url: str
    fast_layer_probability: float
    trigger_deep_layer: bool
    deep_layer_scanned: bool
    deep_layer_indicators: List[str]
    final_decision: str
    is_phishing: bool
    model_status: str


def extract_url_features(url: str) -> List[int]:
    parsed = urlparse(url)
    if not parsed.scheme:
        raise ValueError("URL must include a valid scheme such as http:// or https://")

    normalized_url = url.strip().lower()
    domain = parsed.netloc.lower()

    def count_other_special_chars(text: str) -> int:
        return sum(1 for ch in text if ch in SPECIAL_CHARACTERS)

    return [
        len(normalized_url),
        len(domain),
        int(bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain))),
        max(0, domain.count(".") - 1),
        sum(1 for ch in normalized_url if ch.isalpha()),
        sum(1 for ch in normalized_url if ch.isdigit()),
        normalized_url.count("="),
        normalized_url.count("?"),
        normalized_url.count("&"),
        count_other_special_chars(normalized_url),
        int(parsed.scheme == "https"),
    ]


def get_phishing_probability(url: str) -> float:
    if model is None:
        raise RuntimeError("Model is not loaded")

    features = extract_url_features(url)
    input_vector = [features]

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(input_vector)
        if model_classes is not None and 1 in list(model_classes):
            positive_index = list(model_classes).index(1)
            return float(probabilities[0][positive_index])
        return float(probabilities[0][-1])

    if hasattr(model, "predict"):
        prediction = model.predict(input_vector)
        return float(prediction[0])

    raise RuntimeError("Loaded model does not support probability prediction")


def scan_live_html(url: str) -> dict:
    try:
        response = requests.get(url, timeout=DEEP_SCAN_TIMEOUT, headers={"User-Agent": "PhishingDetector/1.0"})
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to fetch live HTML: {exc}") from exc

    soup = BeautifulSoup(response.content, "html.parser")
    title_text = soup.title.string.strip() if soup.title and soup.title.string else ""
    indicators = []

    title_lower = title_text.lower()
    if any(keyword in title_lower for keyword in BRAND_KEYWORDS):
        indicators.append("BrandKeywordInTitle")

    if soup.find("input", {"type": "password"}):
        indicators.append("HasPasswordField")

    login_form_found = False
    for form in soup.find_all("form"):
        form_text = " ".join(
            (form.get(attr) or "").lower() for attr in ("id", "name", "action", "method")
        )
        if any(term in form_text for term in ("login", "signin", "sign-in")):
            login_form_found = True
            break

        if form.find("input", {"type": ["password"]}):
            login_form_found = True
            break

    if login_form_found:
        indicators.append("HasLoginForm")

    return {
        "indicators": sorted(set(indicators)),
        "page_title": title_text,
    }


@app.get("/")
def health_check():
    return {
        "status": "ok",
        "model_status": model_status,
        "deep_scan_timeout_seconds": DEEP_SCAN_TIMEOUT,
    }


@app.post("/predict", response_model=PredictionResult)
def predict_phishing(request: URLRequest):
    if model is None:
        raise HTTPException(status_code=503, detail="Phishing model is unavailable")

    probability = get_phishing_probability(str(request.url))
    trigger_deep_layer = 0.15 < probability < 0.85
    deep_scan_result = {"indicators": []}

    if trigger_deep_layer:
        try:
            deep_scan_result = scan_live_html(str(request.url))
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc))

    final_decision = "Phishing" if probability >= 0.85 or deep_scan_result["indicators"] else "Legitimate"
    if trigger_deep_layer and not deep_scan_result["indicators"]:
        final_decision = "Legitimate"

    return PredictionResult(
        url=str(request.url),
        fast_layer_probability=round(probability, 4),
        trigger_deep_layer=trigger_deep_layer,
        deep_layer_scanned=trigger_deep_layer,
        deep_layer_indicators=deep_scan_result["indicators"],
        final_decision=final_decision,
        is_phishing=final_decision == "Phishing",
        model_status=model_status,
    )
