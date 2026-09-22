import { describe, it, expect } from "vitest";
import { sanitizeTextInput } from "@/lib/sanitization";
import { parseAndValidateUrl, evaluateUrlRiskPatterns } from "@/lib/url-analyzer";
import { extractEntitiesFromText } from "@/lib/json-parser";
import { calculateScamThreatIndex } from "@/lib/scoring";
import { VerificationResult } from "@/types/analysis";

describe("End-to-End Forensic Evaluation Scenarios", () => {
  it("Scenario 1: Standard Corporate Offer Letter (Safe / Low Risk)", () => {
    const rawInput = `
      Offer of Employment: Senior Frontend Developer
      Company: Tata Consultancy Services
      Contact: careers.talent@tcs.com
      Portal: https://www.tcs.com/careers

      Dear Candidate,
      We are delighted to extend an offer for the position of Senior Frontend Developer.
      Your starting annual compensation will be Rs. 2,400,000.
      No fees or deposits are required for processing your application or equipment.
      Please sign and return the attached agreement by the end of this month.
    `;

    // 1. Sanitization
    const sanitization = sanitizeTextInput(rawInput);
    expect(sanitization.isValid).toBe(true);

    // 2. Entity Recovery
    const entities = extractEntitiesFromText(sanitization.sanitized);
    expect(entities.companyName).toBe("Tata Consultancy Services");
    expect(entities.contactInfo).toContain("careers.talent@tcs.com");
    expect(entities.urls).toContain("https://www.tcs.com/careers");

    // 3. Simulated AI verification result for safe correspondence
    const verificationResult: VerificationResult = {
      summary: "Standard corporate employment offer with legitimate company domain and transparent terms.",
      riskSignals: [],
      recommendedActions: ["Review offer terms and submit accepted copy via corporate portal."],
      extractedEntities: entities,
      suspiciousClaims: [],
      paymentRequests: false,
      sensitiveDataRequests: false,
      urgencyIndicators: false,
      impersonationIndicators: false,
      confidence: 0.95,
      limitations: "Text evaluation only.",
    };

    // 4. Scoring
    const report = calculateScamThreatIndex(verificationResult);

    expect(report.scamThreatIndex).toBe(5);
    expect(report.severityLevel).toBe("Low");
    expect(report.details.extractedEntities.companyName).toBe("Tata Consultancy Services");
    expect(report.details.paymentRequests).toBe(false);
  });

  it("Scenario 2: Advance-Fee Check Equipment Scam (Critical / Very High Risk)", () => {
    const scamEmail = `
      URGENT: IMMEDIATE HIRE CONFIRMATION
      Company: Amazon Global Logistics
      Recruiter: hr-amazon-support@gmail.com
      Interview via Telegram: t.me/amazon_hiring_dept

      Congratulations! You have been selected without further interview.
      We will mail you a cashier check for $3,850 to purchase your MacBook Pro and home office kit.
      You must deposit this check immediately and wire $3,200 back to our designated vendor within 24 hours.
      Failure to deposit and wire funds today will forfeit your position.
    `;

    // 1. Sanitization
    const sanitization = sanitizeTextInput(scamEmail);
    expect(sanitization.isValid).toBe(true);

    // 2. Entity Recovery
    const entities = extractEntitiesFromText(sanitization.sanitized);
    expect(entities.companyName).toBe("Amazon Global Logistics");
    expect(entities.contactInfo).toContain("hr-amazon-support@gmail.com");
    expect(entities.contactInfo).toContain("t.me/amazon_hiring_dept");

    // 3. Verification model output with red flags
    const verificationResult: VerificationResult = {
      summary: "Classic advance-fee fake check scam. Candidate asked to deposit fake check and wire funds to equipment vendor.",
      riskSignals: [
        {
          category: "Payment Request",
          severity: "critical",
          description: "Candidate instructed to wire money to third-party equipment vendor.",
          evidence: "deposit this check immediately and wire $3,200 back to our designated vendor",
          weight: 1.0,
        },
        {
          category: "Impersonation",
          severity: "high",
          description: "Free Gmail address used claiming to represent Amazon Global.",
          evidence: "hr-amazon-support@gmail.com",
          weight: 1.0,
        },
        {
          category: "Urgency",
          severity: "high",
          description: "Aggressive 24-hour threat to forfeit employment.",
          evidence: "wire funds within 24 hours. Failure ... will forfeit your position",
          weight: 1.0,
        },
      ],
      recommendedActions: [
        "Do not deposit the cashier check.",
        "Do not wire any money.",
        "Report to National Cyber Crime Portal (cybercrime.gov.in).",
      ],
      extractedEntities: entities,
      suspiciousClaims: ["Immediate hire without interview", "Check deposit and wire return"],
      paymentRequests: true,
      sensitiveDataRequests: true,
      urgencyIndicators: true,
      impersonationIndicators: true,
      confidence: 0.99,
      limitations: "Text evaluation.",
    };

    // 4. Scoring
    const report = calculateScamThreatIndex(verificationResult);

    expect(report.scamThreatIndex).toBeGreaterThanOrEqual(80);
    expect(report.severityLevel).toBe("Very High");
    expect(report.details.paymentRequests).toBe(true);
    expect(report.details.impersonationIndicators).toBe(true);
  });

  it("Scenario 3: Typosquatted Phishing Portal Link (Malicious URL Flagging)", () => {
    const maliciousUrl = "https://amaz0n-jobs-security-verify.com/login?token=abc";

    // 1. URL parsing & SSRF validation
    const validation = parseAndValidateUrl(maliciousUrl);
    expect(validation.isValid).toBe(true);
    expect(validation.isRestricted).toBe(false);

    // 2. Pure heuristic risk evaluation
    const heuristics = evaluateUrlRiskPatterns(validation.normalizedUrl);
    expect(heuristics.isSuspicious).toBe(true);
    expect(heuristics.signals.some((s) => s.category === "Impersonation")).toBe(true);

    // 3. Verification result combining URL heuristics
    const verificationResult: VerificationResult = {
      summary: "Typosquatted domain mimicking Amazon with deceptive login parameters.",
      riskSignals: heuristics.signals,
      recommendedActions: ["Do not enter credentials or passwords.", "Block sender domain."],
      extractedEntities: {
        companyName: "Amazon (Spoofed)",
        urls: [maliciousUrl],
      },
      suspiciousClaims: ["Official login portal"],
      paymentRequests: false,
      sensitiveDataRequests: true,
      urgencyIndicators: false,
      impersonationIndicators: true,
      confidence: 0.94,
      limitations: "URL inspection only.",
    };

    // 4. Scoring
    const report = calculateScamThreatIndex(verificationResult);

    expect(report.scamThreatIndex).toBeGreaterThanOrEqual(60);
    expect(["High", "Very High"]).toContain(report.severityLevel);
    expect(report.details.impersonationIndicators).toBe(true);
  });
});
