import OpenAI from "openai";
import { cleanAndParseJson, extractEntitiesFromText } from "./json-parser";
import { VerificationResult } from "@/types/analysis";

const openai = new OpenAI({
  apiKey: process.env.FREELLM_API_KEY || "not_needed",
  baseURL: process.env.FREELLM_API_URL || "http://127.0.0.1:31415/v1",
});

const MODEL_NAME = process.env.FREELLM_MODEL || "gemini-3.6-flash";

export async function generateContent(prompt: string): Promise<string> {
  const response = await openai.chat.completions.create({
    model: MODEL_NAME,
    messages: [{ role: "user", content: prompt }],
    temperature: 0.2, // Low temperature for more objective analysis
  });

  return response.choices[0]?.message?.content || "{}";
}

export async function analyzeOfferContent(text: string, imageBase64?: string) {
  const systemPrompt = `You are VERIXA, an objective, highly calibrated AI forensic security analyst specializing in identifying job scams, phishing attempts, spoofed organizations, and fraudulent offers.

Analyze the provided input fairly, forensically, and realistically:
- Carefully identify the Claimed Entity or Organization: Look for company names, sender brand references, employer letterheads, signatures, or recruiters named in the message or screenshot. If a company is mentioned (e.g., "Google", "Amazon", "Infosys", "Tata", "Telegram Recruiter", etc.), extract it accurately in extractedEntities.companyName.
- Extract sender contact details (email addresses, phone numbers, Telegram handles, WhatsApp links) in extractedEntities.contactInfo.
- Extract all mentioned domains, URLs, or portals in extractedEntities.urls.
- Provide a clear, concise forensic summary (2-3 sentences) evaluating what this message claims to be, what red flags or safe characteristics were found, and the overall risk verdict.
- Do NOT exaggerate normal corporate communications into critical scams.
- Only assign "high" or "critical" severity to clear red flags (e.g., upfront payment demands for equipment, crypto/gift card requests, obvious phishing domains, interview via Telegram/WhatsApp without interview process, or credential harvesting).

Return ONLY valid JSON matching this exact schema, with no markdown formatting wrappers around it:
{
  "summary": "Forensic synopsis of the correspondence, evaluating the claimed entity and overall risk.",
  "riskSignals": [
    {
      "category": "Payment Request | Urgency | Impersonation | Suspicious URL | Normal",
      "severity": "low | medium | high | critical",
      "description": "Clear explanation of why this signal was noted.",
      "evidence": "Quoted text or detail from input",
      "weight": 1.0
    }
  ],
  "recommendedActions": ["Specific safety action for the user"],
  "extractedEntities": {
    "companyName": "Accurate claimed company, organization, or employer name",
    "contactInfo": "Sender emails, phone numbers, or messaging handles",
    "urls": ["https://example.com"]
  },
  "suspiciousClaims": [],
  "paymentRequests": false,
  "sensitiveDataRequests": false,
  "urgencyIndicators": false,
  "impersonationIndicators": false,
  "confidence": 0.9,
  "limitations": "Analysis based on provided text/image only."
}`;

  const messages: any[] = [
    { role: "system", content: systemPrompt },
  ];

  if (imageBase64) {
    messages.push({
      role: "user",
      content: [
        { type: "text", text: text || "Analyze this screenshot image for phishing or scam indicators." },
        {
          type: "image_url",
          image_url: {
            url: `data:image/jpeg;base64,${imageBase64}`,
          },
        },
      ],
    });
  } else {
    messages.push({ role: "user", content: text });
  }

  const response = await openai.chat.completions.create({
    model: MODEL_NAME,
    messages: messages,
    temperature: 0.2,
  });

  const rawText = response.choices[0]?.message?.content || "{}";
  const parsed = cleanAndParseJson<VerificationResult>(rawText);

  // Pure heuristic recovery for any missing entities
  if (text) {
    parsed.extractedEntities = extractEntitiesFromText(text, parsed.extractedEntities);
  }

  return parsed;
}