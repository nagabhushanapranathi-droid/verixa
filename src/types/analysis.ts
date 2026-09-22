export type Severity = "low" | "medium" | "high" | "critical";

export interface RiskSignal {
  category: string;
  severity: Severity;
  description: string;
  evidence: string;
  weight: number;
}

export interface VerificationResult {
  summary: string;
  riskSignals: RiskSignal[];
  recommendedActions: string[];
  extractedEntities: {
    companyName?: string;
    contactInfo?: string;
    urls?: string[];
  };
  suspiciousClaims: string[];
  paymentRequests: boolean;
  sensitiveDataRequests: boolean;
  urgencyIndicators: boolean;
  impersonationIndicators: boolean;
  confidence: number;
  limitations: string;
}

export interface FinalAnalysisReport {
  scamThreatIndex: number;
  severityLevel: "Low" | "Caution" | "Moderate" | "High" | "Very High";
  details: VerificationResult;
}
