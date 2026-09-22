import { NextResponse } from "next/server";
import { analyzeOfferContent } from "@/lib/ai";
import { calculateScamThreatIndex } from "@/lib/scoring";

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const { text, imageBase64 } = body;

    if (!text && !imageBase64) {
      return NextResponse.json(
        { error: "Text or image is required for analysis." },
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
          body: JSON.stringify(imageBase64 ? { imageBase64, text } : { text }),
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
      text || "Analyze this image for scam or phishing patterns.",
      imageBase64
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