import { describe, it, expect } from "vitest";
import { calculateScamThreatIndex, getSeverityLevel } from "@/lib/scoring";
import { VerificationResult } from "@/types/analysis";

describe("Scoring Engine: calculateScamThreatIndex & getSeverityLevel", () => {
  it("maps numerical scores correctly to severity levels via getSeverityLevel", () => {
    expect(getSeverityLevel(95)).toBe("Very High");
    expect(getSeverityLevel(80)).toBe("Very High");
    expect(getSeverityLevel(79)).toBe("High");
    expect(getSeverityLevel(60)).toBe("High");
    expect(getSeverityLevel(59)).toBe("Moderate");
    expect(getSeverityLevel(40)).toBe("Moderate");
    expect(getSeverityLevel(39)).toBe("Caution");
    expect(getSeverityLevel(25)).toBe("Caution");
    expect(getSeverityLevel(24)).toBe("Low");
    expect(getSeverityLevel(5)).toBe("Low");
    expect(getSeverityLevel(0)).toBe("Low");
  });

  it("clamps clean corporate text with zero risk signals to baseline safety score (5) and 'Low' severity", () => {
    const benignResult: VerificationResult = {
      summary: "Legitimate software engineer offer letter with standard compensation details.",
      riskSignals: [],
      recommendedActions: ["Review contract details."],
      extractedEntities: { companyName: "Google LLC" },
      suspiciousClaims: [],
      paymentRequests: false,
      sensitiveDataRequests: false,
      urgencyIndicators: false,
      impersonationIndicators: false,
      confidence: 0.95,
      limitations: "Text only.",
    };

    const report = calculateScamThreatIndex(benignResult);

    expect(report.scamThreatIndex).toBe(5);
    expect(report.severityLevel).toBe("Low");
    expect(report.details.riskSignals).toHaveLength(0);
    expect(report.details.confidence).toBe(0.95);
  });

  it("calculates high threat score for advance fee and equipment payment scam", () => {
    const paymentScamResult: VerificationResult = {
      summary: "Candidate instructed to purchase home office equipment using cashier check.",
      riskSignals: [
        {
          category: "Payment Request",
          severity: "critical",
          description: "Candidate asked to pay $1,500 for home office vendor equipment.",
          evidence: "Wire $1,500 to our certified vendor via Zelle or crypto.",
          weight: 1.0,
        },
        {
          category: "Impersonation",
          severity: "high",
          description: "Free webmail address used for official enterprise correspondence.",
          evidence: "hr-google-recruitment@gmail.com",
          weight: 1.0,
        },
      ],
      recommendedActions: ["Cease communication immediately.", "Do not wire money."],
      extractedEntities: {
        companyName: "Google",
        contactInfo: "hr-google-recruitment@gmail.com",
      },
      suspiciousClaims: ["Immediate hiring without technical interview"],
      paymentRequests: true,
      sensitiveDataRequests: true,
      urgencyIndicators: true,
      impersonationIndicators: true,
      confidence: 0.98,
      limitations: "Text only.",
    };

    const report = calculateScamThreatIndex(paymentScamResult);

    // 10 baseline + 35 (crit) + 25 (high) + 20 (payment) + 15 (sensitive data) + 10 (urgency) + 20 (impersonation) = 135 -> clamped to 99
    expect(report.scamThreatIndex).toBe(99);
    expect(report.severityLevel).toBe("Very High");
    expect(report.details.paymentRequests).toBe(true);
    expect(report.details.impersonationIndicators).toBe(true);
  });

  it("calculates proportional score for moderate / caution warnings", () => {
    const cautionResult: VerificationResult = {
      summary: "Email has vague job description and urgent reply window.",
      riskSignals: [
        {
          category: "Urgency",
          severity: "medium",
          description: "Short deadline provided to sign offer.",
          evidence: "Sign within 12 hours.",
          weight: 1.0,
        },
      ],
      recommendedActions: ["Request formal written extension."],
      extractedEntities: {},
      suspiciousClaims: [],
      paymentRequests: false,
      sensitiveDataRequests: false,
      urgencyIndicators: true,
      impersonationIndicators: false,
      confidence: 0.75,
      limitations: "Text only.",
    };

    const report = calculateScamThreatIndex(cautionResult);

    // 10 baseline + 15 (med signal) + 10 (urgency) = 35 -> Caution
    expect(report.scamThreatIndex).toBe(35);
    expect(report.severityLevel).toBe("Caution");
  });

  it("provides sensible default fallbacks when optional fields are omitted", () => {
    const minimalResult = {
      summary: "",
      riskSignals: [],
      paymentRequests: false,
      sensitiveDataRequests: false,
      urgencyIndicators: false,
      impersonationIndicators: false,
    } as unknown as VerificationResult;

    const report = calculateScamThreatIndex(minimalResult);

    expect(report.scamThreatIndex).toBe(5);
    expect(report.severityLevel).toBe("Low");
    expect(report.details.recommendedActions).toBeDefined();
    expect(report.details.recommendedActions.length).toBeGreaterThan(0);
    expect(report.details.confidence).toBe(0.85);
  });

  it("never exceeds 99 or falls below 5 even under extreme signal weights", () => {
    const extremeResult: VerificationResult = {
      summary: "Massive fraud payload with 10 critical signals",
      riskSignals: Array(10).fill({
        category: "Critical",
        severity: "critical",
        description: "Severe threat",
        evidence: "evidence",
        weight: 5.0,
      }),
      recommendedActions: [],
      extractedEntities: {},
      suspiciousClaims: [],
      paymentRequests: true,
      sensitiveDataRequests: true,
      urgencyIndicators: true,
      impersonationIndicators: true,
      confidence: 1.0,
      limitations: "",
    };

    const report = calculateScamThreatIndex(extremeResult);
    expect(report.scamThreatIndex).toBe(99);
  });
});
