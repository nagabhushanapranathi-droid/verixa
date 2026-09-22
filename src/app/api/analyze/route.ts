import { NextResponse } from "next/server";
import { analyzeOfferContent } from "@/lib/ai";
import { calculateScamThreatIndex } from "@/lib/scoring";
import { sanitizeTextInput, sanitizeBase64Image } from "@/lib/sanitization";

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const { text, imageBase64 } = body;

    let sanitizedText: string | undefined;
    let sanitizedImage: string | undefined;

    if (text !== undefined && text !== null) {
      const textResult = sanitizeTextInput(text);
      if (!textResult.isValid && !imageBase64) {
        return NextResponse.json({ error: textResult.error }, { status: 400 });
      }
      if (textResult.isValid) {
        sanitizedText = textResult.sanitized;
      }
    }

    if (imageBase64 !== undefined && imageBase64 !== null) {
      const imageResult = sanitizeBase64Image(imageBase64);
      if (!imageResult.isValid && !sanitizedText) {
        return NextResponse.json({ error: imageResult.error }, { status: 400 });
      }
      if (imageResult.isValid) {
        sanitizedImage = imageResult.sanitized;
      }
    }

    if (!sanitizedText && !sanitizedImage) {
      return NextResponse.json(
        { error: "Valid correspondence text or document image is required for analysis." },
        { status: 400 }
      );
    }

    // If a dedicated FastAPI backend URL is configured, forward the request
    const fastApiUrl = process.env.FASTAPI_BACKEND_URL;
    if (fastApiUrl) {
      const endpoint = imageBase64 ? `${fastApiUrl}/analyze/image` : `${fastApiUrl}/analyze/text`;
      try {
        const fastApiResponse = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(sanitizedImage ? { imageBase64: sanitizedImage, text: sanitizedText } : { text: sanitizedText }),
        });
        if (fastApiResponse.ok) {
          const fastApiData = await fastApiResponse.json();
          return NextResponse.json(fastApiData);
        }
      } catch (fastApiErr) {
        console.warn("FastAPI backend forward failed, falling back to direct FreeLLMAPI:", fastApiErr);
      }
    }

    // Direct FreeLLMAPI processing
    const verificationResult = await analyzeOfferContent(
      sanitizedText || "Analyze this image for scam or phishing patterns.",
      sanitizedImage
    );
    const finalReport = calculateScamThreatIndex(verificationResult);

    return NextResponse.json(finalReport);
  } catch (err: any) {
    console.error("API Error in /api/analyze:", err);
    const isTimeout = err?.name === "AbortError" || err?.message?.includes("timeout");
    const isConnRefused = err?.code === "ECONNREFUSED" || err?.message?.includes("Connection error");
    const status = isTimeout ? 504 : 500;
    const message = isTimeout
      ? "FreeLLMAPI request timed out. Please verify your proxy server status."
      : isConnRefused
      ? `Unable to connect to FreeLLMAPI proxy at ${process.env.FREELLM_API_URL || "http://localhost:3001/v1"}. Ensure your proxy is running.`
      : err?.message || "Failed to analyze content.";

    return NextResponse.json({ error: message }, { status });
  }
}