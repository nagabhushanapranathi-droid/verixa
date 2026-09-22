/**
 * Pure, stateless URL forensic and security validation functions.
 * Analyzes network boundary safety (SSRF protection), domain heuristics,
 * and malicious patterns without side effects or network calls.
 */

import { RiskSignal } from "@/types/analysis";

export interface UrlValidationResult {
  isValid: boolean;
  parsedUrl?: URL;
  normalizedUrl: string;
  isRestricted: boolean;
  error?: string;
}

export interface UrlRiskEvaluation {
  riskScore: number; // 0 to 100
  isSuspicious: boolean;
  signals: RiskSignal[];
  suspiciousReasons: string[];
}

/**
 * Checks if a given URL targets restricted/private networks or dangerous protocols.
 * Guards against Server-Side Request Forgery (SSRF) and local network enumeration.
 */
export function isRestrictedNetworkUrl(urlString: string): boolean {
  if (!urlString || typeof urlString !== "string") {
    return true;
  }

  const trimmed = urlString.trim().toLowerCase();

  // Guard against non-http(s) protocols
  if (
    trimmed.startsWith("file:") ||
    trimmed.startsWith("ftp:") ||
    trimmed.startsWith("gopher:") ||
    trimmed.startsWith("data:") ||
    trimmed.startsWith("javascript:")
  ) {
    return true;
  }

  try {
    const url = new URL(trimmed.startsWith("http") ? trimmed : `https://${trimmed}`);
    const hostname = url.hostname.toLowerCase();

    // Loopback hostnames & IPs
    if (
      hostname === "localhost" ||
      hostname.endsWith(".localhost") ||
      hostname === "127.0.0.1" ||
      hostname === "::1" ||
      hostname === "[::1]" ||
      hostname === "0.0.0.0"
    ) {
      return true;
    }

    // Link-local / AWS metadata IP
    if (hostname === "169.254.169.254" || hostname.startsWith("169.254.")) {
      return true;
    }

    // RFC 1918 Private IPv4 Ranges
    // 10.0.0.0 - 10.255.255.255
    if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      return true;
    }

    // 192.168.0.0 - 192.168.255.255
    if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      return true;
    }

    // 172.16.0.0 - 172.31.255.255
    const match172 = hostname.match(/^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
    if (match172) {
      const secondOctet = parseInt(match172[1], 10);
      if (secondOctet >= 16 && secondOctet <= 31) {
        return true;
      }
    }

    // Dotless IP formats or hex/octal localhost bypasses (e.g., 2130706433, 0177.1)
    if (/^\d+$/.test(hostname)) {
      return true;
    }

    return false;
  } catch {
    return true;
  }
}

/**
 * Parses and validates an input URL.
 * Automatically adds https:// protocol if omitted.
 */
export function parseAndValidateUrl(rawUrl: string): UrlValidationResult {
  if (!rawUrl || typeof rawUrl !== "string") {
    return {
      isValid: false,
      normalizedUrl: "",
      isRestricted: false,
      error: "A valid URL string is required.",
    };
  }

  const trimmed = rawUrl.trim();
  if (trimmed.length === 0) {
    return {
      isValid: false,
      normalizedUrl: "",
      isRestricted: false,
      error: "URL string cannot be empty.",
    };
  }

  const urlToParse = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  try {
    const parsed = new URL(urlToParse);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return {
        isValid: false,
        normalizedUrl: urlToParse,
        isRestricted: true,
        error: `Unsupported protocol: ${parsed.protocol}. Only HTTP and HTTPS are permitted.`,
      };
    }

    if (!parsed.hostname || !parsed.hostname.includes(".")) {
      // Except localhost which is restricted
      if (parsed.hostname !== "localhost") {
        return {
          isValid: false,
          normalizedUrl: urlToParse,
          isRestricted: false,
          error: "URL must contain a valid domain name with an extension.",
        };
      }
    }

    const restricted = isRestrictedNetworkUrl(parsed.href);

    return {
      isValid: !restricted,
      parsedUrl: parsed,
      normalizedUrl: parsed.href,
      isRestricted: restricted,
      error: restricted ? "URL points to a restricted internal or loopback network." : undefined,
    };
  } catch {
    return {
      isValid: false,
      normalizedUrl: urlToParse,
      isRestricted: false,
      error: "Malformed URL syntax.",
    };
  }
}

/**
 * Pure heuristic evaluation for common phishing, typosquatting, and deceptive patterns.
 */
export function evaluateUrlRiskPatterns(urlString: string): UrlRiskEvaluation {
  const validation = parseAndValidateUrl(urlString);
  if (!validation.isValid || !validation.parsedUrl) {
    return {
      riskScore: 85,
      isSuspicious: true,
      signals: [
        {
          category: "Suspicious URL",
          severity: "high",
          description: validation.error || "Malformed or restricted URL structure.",
          evidence: urlString,
          weight: 1.0,
        },
      ],
      suspiciousReasons: [validation.error || "Malformed URL"],
    };
  }

  const signals: RiskSignal[] = [];
  const reasons: string[] = [];
  let score = 0;

  const url = validation.parsedUrl;
  const hostname = url.hostname.toLowerCase();
  const pathname = url.pathname.toLowerCase();

  // Pattern 1: Raw IP used as host instead of domain
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    score += 45;
    reasons.push("Host uses a direct IP address rather than an established domain name.");
    signals.push({
      category: "Suspicious URL",
      severity: "critical",
      description: "Direct IP address host typically associated with ephemeral phishing servers.",
      evidence: hostname,
      weight: 1.2,
    });
  }

  // Pattern 2: Typosquatting / brand spoofing in subdomains or misleading SLD
  const spoofedBrands = [
    { target: "google", typos: ["goog1e", "g00gle", "google-security", "google-verify"] },
    { target: "amazon", typos: ["amaz0n", "arnazon", "amazon-jobs", "amazon-career-portal"] },
    { target: "paypal", typos: ["paypa1", "pay-pal", "paypal-service", "paypal-auth"] },
    { target: "microsoft", typos: ["micros0ft", "micro-soft", "ms-office-verify"] },
    { target: "apple", typos: ["app1e", "apple-id-verify", "apple-icloud-secure"] },
    { target: "infosys", typos: ["inf0sys", "infosys-careers-portal", "infosys-hr"] },
  ];

  for (const { target, typos } of spoofedBrands) {
    for (const typo of typos) {
      if (hostname.includes(typo) && !hostname.endsWith(`.${target}.com`) && hostname !== `${target}.com`) {
        score += 50;
        reasons.push(`Suspicious brand impersonation pattern resembling ${target}: "${typo}"`);
        signals.push({
          category: "Impersonation",
          severity: "critical",
          description: `Typosquatted domain mimicking legitimate brand ${target}.`,
          evidence: typo,
          weight: 1.5,
        });
      }
    }
  }

  // Pattern 3: Excessive subdomain depth (e.g. login.verify.account.careers.security.xyz)
  const parts = hostname.split(".");
  if (parts.length > 4) {
    score += 40;
    reasons.push("Excessive subdomain depth often used to obscure real origin domain.");
    signals.push({
      category: "Suspicious URL",
      severity: "high",
      description: "Multiple subdomain tiers detected, obscuring destination ownership.",
      evidence: hostname,
      weight: 1.0,
    });
  }

  // Pattern 4: Suspicious keywords combined with non-corporate paths
  if (
    (hostname.includes("login") || hostname.includes("verify") || hostname.includes("secure") || hostname.includes("account")) &&
    (pathname.includes("signin") || pathname.includes("wallet") || pathname.includes("password"))
  ) {
    score += 25;
    reasons.push("Phishing keyword combination detected across hostname and path.");
    signals.push({
      category: "Suspicious URL",
      severity: "high",
      description: "Credential harvesting signature in URL path and hostname.",
      evidence: `${hostname}${pathname}`,
      weight: 1.0,
    });
  }

  return {
    riskScore: Math.min(score, 100),
    isSuspicious: score >= 40,
    signals,
    suspiciousReasons: reasons,
  };
}
