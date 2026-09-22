import { NextResponse } from "next/server";
import { generateContent } from "@/lib/ai";
import { calculateScamThreatIndex } from "@/lib/scoring";

export async function POST(req: Request) {
  try {
    const { url } = await req.json();

    if (!url || typeof url !== "string") {
      return NextResponse.json({ error: "A valid URL is required." }, { status: 400 });
    }

    // Basic SSRF check to prevent scanning local network loops
    if (
      url.includes("localhost") ||
      url.includes("127.0.0.1") ||
      url.startsWith("http://192.168.") ||
      url.startsWith("http://10.")
    ) {
      return NextResponse.json({ error: "Restricted network URL." }, { status: 400 });
    }

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
    const cleanedText = rawResponse.replace(/```json/g, "").replace(/```/g, "").trim();
    
    const verificationResult = JSON.parse(cleanedText);
    const finalReport = calculateScamThreatIndex(verificationResult);

    return NextResponse.json(finalReport);
  } catch (err: any) {
    console.error("URL Analysis API Error:", err);
    return NextResponse.json({ error: err.message || "Failed to analyze URL." }, { status: 500 });
  }
}