import { NextResponse } from "next/server";
import { generateContent } from "@/lib/ai";
import { calculateScamThreatIndex } from "@/lib/scoring";
import { parseAndValidateUrl, evaluateUrlRiskPatterns } from "@/lib/url-analyzer";
import { cleanAndParseJson } from "@/lib/json-parser";
import { VerificationResult } from "@/types/analysis";

export async function POST(req: Request) {
  try {
    const { url } = await req.json();

    const validation = parseAndValidateUrl(url);
    if (!validation.isValid) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }

    const normalizedUrl = validation.normalizedUrl;
    const localRisk = evaluateUrlRiskPatterns(normalizedUrl);

    const prompt = `You are a cybersecurity URL and phishing analyst. Analyze this URL for typosquatting, phishing patterns, fake career portal indicators, or malicious structure: "${url}".

Return ONLY valid JSON matching this exact schema, with no markdown formatting wrappers:
{
  "summary": "Analysis of the URL structure and domain threat level.",
  "riskSignals": [
    {
      "category": "Suspicious URL",
      "severity": "low | medium | high | critical",
      "description": "Why this domain or link pattern is dangerous or safe",
      "evidence": "${url}",
      "weight": 1.0
    }
  ],
  "recommendedActions": ["Do not click if suspicious", "Verify domain ownership"],
  "extractedEntities": {
    "companyName": "Brand or entity being impersonated or domain owner",
    "contactInfo": "None or associated registration",
    "urls": ["${url}"]
  },
  "confidence": 0.85,
  "paymentRequests": false,
  "sensitiveDataRequests": true,
  "urgencyIndicators": false,
  "impersonationIndicators": true
}`;

    const rawResponse = await generateContent(prompt);
    const verificationResult = cleanAndParseJson<VerificationResult>(rawResponse);

    // Merge any locally flagged critical heuristic signals (e.g. typosquatting or IP host)
    if (localRisk.signals.length > 0) {
      verificationResult.riskSignals = [
        ...localRisk.signals,
        ...(verificationResult.riskSignals || []),
      ];
      if (localRisk.isSuspicious) {
        verificationResult.impersonationIndicators = true;
      }
    }

    const finalReport = calculateScamThreatIndex(verificationResult);

    return NextResponse.json(finalReport);
  } catch (err: any) {
    console.error("URL Analysis API Error:", err);
    return NextResponse.json({ error: err.message || "Failed to analyze URL." }, { status: 500 });
  }
}