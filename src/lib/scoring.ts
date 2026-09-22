import { FinalAnalysisReport, VerificationResult } from "@/types/analysis";

export function calculateScamThreatIndex(result: VerificationResult): FinalAnalysisReport {
  let score = 10; // Baseline safety score
  const signals = result.riskSignals || [];

  // Weight-based score accumulation
  signals.forEach((signal) => {
    let multiplier = 1.0;
    if (signal.severity === "critical") multiplier = 35;
    else if (signal.severity === "high") multiplier = 25;
    else if (signal.severity === "medium") multiplier = 15;
    else if (signal.severity === "low") multiplier = 5;

    score += multiplier * (signal.weight || 1.0);
  });

  // Factor in boolean red flags
  if (result.paymentRequests) score += 20;
  if (result.sensitiveDataRequests) score += 15;
  if (result.urgencyIndicators) score += 10;
  if (result.impersonationIndicators) score += 20;

  // Clamp score between 5 and 99 (unless zero signals)
  if (signals.length === 0 && !result.paymentRequests) {
    score = 5;
  } else {
    score = Math.min(Math.max(Math.round(score), 10), 99);
  }

  // Determine severity level label
  let severityLevel: "Low" | "Caution" | "Moderate" | "High" | "Very High" = "Low";
  if (score >= 80) severityLevel = "Very High";
  else if (score >= 60) severityLevel = "High";
  else if (score >= 40) severityLevel = "Moderate";
  else if (score >= 25) severityLevel = "Caution";

  return {
    scamThreatIndex: score,
    severityLevel,
    details: {
      ...result,
      summary: result.summary,
      riskSignals: signals,
      recommendedActions: result.recommendedActions || ["Verify the recruiter's identity through official corporate channels."],
      confidence: result.confidence || 0.85,
    },
  };
}