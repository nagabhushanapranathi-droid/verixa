import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json({
    status: "ok",
    service: "VERIXA Security API",
    provider: "FreeLLMAPI",
    model: process.env.FREELLM_MODEL || "gemini-3.6-flash",
    timestamp: new Date().toISOString(),
  });
}