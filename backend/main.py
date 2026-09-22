import os
import re
import json
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="VERIXA Security Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FREELLM_API_KEY = os.getenv("FREELLM_API_KEY", "dummy-key")
FREELLM_API_URL = os.getenv("FREELLM_API_URL", "http://localhost:3001/v1")
FREELLM_MODEL = os.getenv("FREELLM_MODEL", "gemini-3.6-flash")

client = OpenAI(
    api_key=FREELLM_API_KEY,
    base_url=FREELLM_API_URL,
    timeout=30.0,
)

class RiskSignal(BaseModel):
    category: str
    severity: str  # low | medium | high | critical
    description: str
    evidence: str
    weight: float = 1.0

class VerificationResult(BaseModel):
    summary: str
    riskSignals: List[RiskSignal] = Field(default_factory=list)
    recommendedActions: List[str] = Field(default_factory=list)
    extractedEntities: Dict[str, Any] = Field(default_factory=dict)
    suspiciousClaims: List[str] = Field(default_factory=list)
    paymentRequests: bool = False
    sensitiveDataRequests: bool = False
    urgencyIndicators: bool = False
    impersonationIndicators: bool = False
    confidence: float = 0.85
    limitations: str = "Analysis based on provided input."

class FinalAnalysisReport(BaseModel):
    scamThreatIndex: int
    severityLevel: str
    details: VerificationResult
    summary: str
    riskSignals: List[RiskSignal]
    recommendedActions: List[str]

class TextAnalysisRequest(BaseModel):
    text: str

class UrlAnalysisRequest(BaseModel):
    url: str

class ImageAnalysisRequest(BaseModel):
    imageBase64: str
    text: Optional[str] = "Analyze this screenshot image for phishing, fake job offers, or payment scam demands."

def calculate_scam_threat_index(details: VerificationResult) -> tuple[int, str]:
    total_score = 0.0
    for signal in details.riskSignals:
        multiplier = 12.0
        if signal.severity == "medium":
            multiplier = 20.0
        elif signal.severity == "high":
            multiplier = 30.0
        elif signal.severity == "critical":
            multiplier = 45.0
        total_score += (signal.weight or 1.0) * multiplier

    if details.paymentRequests:
        total_score += 15.0
    if details.sensitiveDataRequests:
        total_score += 15.0
    if details.urgencyIndicators:
        total_score += 10.0
    if details.impersonationIndicators:
        total_score += 15.0

    index = min(max(round(total_score), 0), 100)
    severity_level = "Low"
    if index > 80:
        severity_level = "Very High"
    elif index > 60:
        severity_level = "High"
    elif index > 40:
        severity_level = "Moderate"
    elif index > 20:
        severity_level = "Caution"

    return index, severity_level

def clean_and_parse_json(content: str) -> dict:
    cleaned = content.strip()
    if cleaned.startswith("`json"):
        cleaned = re.sub(r"^`json\s*", "", cleaned)
        cleaned = re.sub(r"\s*`$", "", cleaned)
    elif cleaned.startswith("`"):
        cleaned = re.sub(r"^`\s*", "", cleaned)
        cleaned = re.sub(r"\s*`$", "", cleaned)
    return json.loads(cleaned)

def build_report(raw_json: dict) -> FinalAnalysisReport:
    details = VerificationResult(**raw_json)
    index, severity = calculate_scam_threat_index(details)
    return FinalAnalysisReport(
        scamThreatIndex=index,
        severityLevel=severity,
        details=details,
        summary=details.summary,
        riskSignals=details.riskSignals,
        recommendedActions=details.recommendedActions,
    )

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "VERIXA FastAPI Security Engine",
        "provider": "FreeLLMAPI",
        "model": FREELLM_MODEL,
    }

@app.post("/analyze/text", response_model=FinalAnalysisReport)
def analyze_text(payload: TextAnalysisRequest):
    if not payload.text.strip():
        raise HTTPException(status_code=400, detail="Text content cannot be empty.")

    system_prompt = (
        "You are an elite phishing and scam detection system. Inspect the text for fraudulent job offers, "
        "impersonation, fee/check fraud, and credential harvesting. Output ONLY valid JSON."
    )
    user_prompt = f"""Analyze this content and return JSON matching this schema:
{{
  "summary": "Brief summary",
  "riskSignals": [
    {{
      "category": "Payment Request | Fake Check | Impersonation | Suspicious Contact",
      "severity": "low | medium | high | critical",
      "description": "Explanation",
      "evidence": "Quoted snippet",
      "weight": 1.0
    }}
  ],
  "recommendedActions": ["Safety actions"],
  "extractedEntities": {{"companyName": "Company", "contactInfo": "Contact info"}},
  "suspiciousClaims": [],
  "paymentRequests": false,
  "sensitiveDataRequests": false,
  "urgencyIndicators": false,
  "impersonationIndicators": false,
  "confidence": 0.9,
  "limitations": "Based on provided text."
}}

Text to analyze:
{payload.text}"""

    try:
        response = client.chat.completions.create(
            model=FREELLM_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
        )
        content = response.choices[0].message.content or "{}"
        parsed = clean_and_parse_json(content)
        return build_report(parsed)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"FreeLLMAPI analysis error: {str(e)}")

@app.post("/analyze/url", response_model=FinalAnalysisReport)
def analyze_url(payload: UrlAnalysisRequest):
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # Guardrails
    lower_url = url.lower()
    if any(h in lower_url for h in ["localhost", "127.0.0.1", "192.168.", "10.0."]):
        raise HTTPException(status_code=400, detail="Local and private network URLs are restricted.")

    system_prompt = "You are a web security analyzer specializing in phishing domains and scam URLs. Output strictly JSON."
    user_prompt = f"""Inspect this URL for typosquatting, brand impersonation, deceptive subdomains, or phishing indicators:
{url}

Return JSON with keys: summary, riskSignals (category, severity, description, evidence, weight), recommendedActions, extractedEntities, suspiciousClaims, paymentRequests, sensitiveDataRequests, urgencyIndicators, impersonationIndicators, confidence, limitations."""

    try:
        response = client.chat.completions.create(
            model=FREELLM_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
        )
        content = response.choices[0].message.content or "{}"
        parsed = clean_and_parse_json(content)
        return build_report(parsed)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"FreeLLMAPI URL analysis error: {str(e)}")

@app.post("/analyze/image", response_model=FinalAnalysisReport)
def analyze_image(payload: ImageAnalysisRequest):
    if not payload.imageBase64:
        raise HTTPException(status_code=400, detail="Image base64 data is required.")

    img_url = payload.imageBase64
    if not img_url.startswith("data:"):
        img_url = f"data:image/jpeg;base64,{img_url}"

    system_prompt = "You are an AI document fraud inspector. Analyze the provided screenshot for scam indicators. Output strictly JSON."

    try:
        response = client.chat.completions.create(
            model=FREELLM_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": payload.text or "Inspect this screenshot for phishing or fake offer signals."},
                        {"type": "image_url", "image_url": {"url": img_url}},
                    ],
                },
            ],
            temperature=0.1,
        )
        content = response.choices[0].message.content or "{}"
        parsed = clean_and_parse_json(content)
        return build_report(parsed)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"FreeLLMAPI image analysis error: {str(e)}")
