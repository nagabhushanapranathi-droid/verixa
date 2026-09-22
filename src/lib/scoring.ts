import { FinalAnalysisReport, VerificationResult } from "@/types/analysis";

export type SeverityLevel = "Low" | "Caution" | "Moderate" | "High" | "Very High";

/**
 * Pure mapping from a numerical score (0-100) to human-readable severity level.
 */
export function getSeverityLevel(score: number): SeverityLevel {
  if (score >= 80) return "Very High";
  if (score >= 60) return "High";
  if (score >= 40) return "Moderate";
  if (score >= 25) return "Caution";
  return "Low";
}

/**
 * Pure, stateless scoring function calculating the Scam Threat Index.
 *
 * Scoring Rules:
 * - Baseline score starts at 10.
 * - Accumulates weighted scores for each identified risk signal based on severity.
 * - Adds boolean red flag penalties:
 *   - Payment Requests: +20
 *   - Sensitive Data Demands: +15
 *   - Urgency Pressure: +10
 *   - Impersonation Indicators: +20
 * - Clamps benign content with 0 signals & no payment demand to minimum safety score (5).
 * - Otherwise clamps within bounded range [10, 99].
 */
export function calculateScamThreatIndex(result: VerificationResult): FinalAnalysisReport {
  let score = 10;
  const signals = result.riskSignals || [];

  // Weight-based score accumulation
  signals.forEach((signal) => {
    let multiplier = 1.0;
    if (signal.severity === "critical") multiplier = 35;
    else if (signal.severity === "high") multiplier = 25;
    else if (signal.severity === "medium") multiplier = 15;
    else if (signal.severity === "low") multiplier = 5;

    score += multiplier * (signal.weight ?? 1.0);
  });

  // Factor in boolean red flags
  if (result.paymentRequests) score += 20;
  if (result.sensitiveDataRequests) score += 15;
  if (result.urgencyIndicators) score += 10;
  if (result.impersonationIndicators) score += 20;

  // Clamp score between 5 and 99 (unless zero signals & no payment requests)
  if (signals.length === 0 && !result.paymentRequests) {
    score = 5;
  } else {
    score = Math.min(Math.max(Math.round(score), 10), 99);
  }

  const severityLevel = getSeverityLevel(score);

  return {
    scamThreatIndex: score,
    severityLevel,
    details: {
      ...result,
      summary: result.summary || "Forensic analysis completed.",
      riskSignals: signals,
      recommendedActions: result.recommendedActions && result.recommendedActions.length > 0
        ? result.recommendedActions
        : ["Verify the sender's identity through official corporate channels before proceeding."],
      confidence: typeof result.confidence === "number" ? result.confidence : 0.85,
    },
  };
}