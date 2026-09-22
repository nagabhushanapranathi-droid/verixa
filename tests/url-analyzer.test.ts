import { describe, it, expect } from "vitest";
import {
  isRestrictedNetworkUrl,
  parseAndValidateUrl,
  evaluateUrlRiskPatterns,
} from "@/lib/url-analyzer";

describe("URL Forensic & Security Engine: url-analyzer", () => {
  describe("isRestrictedNetworkUrl (SSRF Guard)", () => {
    it("blocks localhost and loopback interfaces", () => {
      expect(isRestrictedNetworkUrl("http://localhost")).toBe(true);
      expect(isRestrictedNetworkUrl("http://localhost:3000")).toBe(true);
      expect(isRestrictedNetworkUrl("https://sub.localhost")).toBe(true);
      expect(isRestrictedNetworkUrl("http://127.0.0.1")).toBe(true);
      expect(isRestrictedNetworkUrl("http://127.0.0.1:8080/admin")).toBe(true);
      expect(isRestrictedNetworkUrl("http://[::1]")).toBe(true);
      expect(isRestrictedNetworkUrl("http://0.0.0.0")).toBe(true);
    });

    it("blocks private RFC 1918 IPv4 ranges", () => {
      // 10.x.x.x
      expect(isRestrictedNetworkUrl("http://10.0.0.1")).toBe(true);
      expect(isRestrictedNetworkUrl("http://10.254.1.10/login")).toBe(true);

      // 192.168.x.x
      expect(isRestrictedNetworkUrl("http://192.168.1.1")).toBe(true);
      expect(isRestrictedNetworkUrl("http://192.168.0.254/status")).toBe(true);

      // 172.16-31.x.x
      expect(isRestrictedNetworkUrl("http://172.16.0.1")).toBe(true);
      expect(isRestrictedNetworkUrl("http://172.24.10.5")).toBe(true);
      expect(isRestrictedNetworkUrl("http://172.31.255.255")).toBe(true);
      // Public 172 outside range should not be restricted
      expect(isRestrictedNetworkUrl("http://172.32.0.1")).toBe(false);
      expect(isRestrictedNetworkUrl("http://172.15.0.1")).toBe(false);
    });

    it("blocks cloud metadata service IP", () => {
      expect(isRestrictedNetworkUrl("http://169.254.169.254/latest/meta-data/")).toBe(true);
    });

    it("blocks non-HTTP protocols", () => {
      expect(isRestrictedNetworkUrl("file:///etc/passwd")).toBe(true);
      expect(isRestrictedNetworkUrl("ftp://files.example.com")).toBe(true);
      expect(isRestrictedNetworkUrl("data:text/html;base64,...")).toBe(true);
      expect(isRestrictedNetworkUrl("javascript:alert(1)")).toBe(true);
    });

    it("permits legitimate public internet URLs", () => {
      expect(isRestrictedNetworkUrl("https://www.google.com")).toBe(false);
      expect(isRestrictedNetworkUrl("https://careers.microsoft.com/us/en")).toBe(false);
      expect(isRestrictedNetworkUrl("https://amazon.jobs")).toBe(false);
      expect(isRestrictedNetworkUrl("https://cybercrime.gov.in")).toBe(false);
    });
  });

  describe("parseAndValidateUrl", () => {
    it("normalizes and validates standard URLs", () => {
      const result = parseAndValidateUrl("https://google.com/jobs");
      expect(result.isValid).toBe(true);
      expect(result.isRestricted).toBe(false);
      expect(result.normalizedUrl).toBe("https://google.com/jobs");
      expect(result.parsedUrl?.hostname).toBe("google.com");
    });

    it("automatically prepends https:// if protocol is omitted", () => {
      const result = parseAndValidateUrl("careers.netflix.com");
      expect(result.isValid).toBe(true);
      expect(result.normalizedUrl).toBe("https://careers.netflix.com/");
      expect(result.parsedUrl?.hostname).toBe("careers.netflix.com");
    });

    it("rejects restricted network targets", () => {
      const result = parseAndValidateUrl("http://127.0.0.1:3000/api");
      expect(result.isValid).toBe(false);
      expect(result.isRestricted).toBe(true);
      expect(result.error).toContain("restricted internal or loopback network");
    });

    it("rejects invalid or malformed URL formats", () => {
      expect(parseAndValidateUrl("").isValid).toBe(false);
      expect(parseAndValidateUrl("   ").isValid).toBe(false);
      expect(parseAndValidateUrl("not a valid url").isValid).toBe(false);
    });
  });

  describe("evaluateUrlRiskPatterns", () => {
    it("flags raw IP addresses used as hostnames", () => {
      const result = evaluateUrlRiskPatterns("http://203.0.113.195/career/verify.html");
      expect(result.isSuspicious).toBe(true);
      expect(result.riskScore).toBeGreaterThanOrEqual(45);
      expect(result.signals.some((s) => s.description.includes("Direct IP address"))).toBe(true);
    });

    it("flags brand typosquatting and impersonation domains", () => {
      const result = evaluateUrlRiskPatterns("https://amaz0n-security-portal.xyz/login");
      expect(result.isSuspicious).toBe(true);
      expect(result.riskScore).toBeGreaterThanOrEqual(50);
      expect(result.signals.some((s) => s.category === "Impersonation")).toBe(true);
    });

    it("flags excessive subdomain nesting", () => {
      const result = evaluateUrlRiskPatterns("https://login.secure.account.verify.careers.portal.phish.com");
      expect(result.isSuspicious).toBe(true);
      expect(result.signals.some((s) => s.description.includes("subdomain"))).toBe(true);
    });

    it("approves genuine corporate domains with low risk score", () => {
      const result = evaluateUrlRiskPatterns("https://careers.google.com/jobs/results/");
      expect(result.isSuspicious).toBe(false);
      expect(result.riskScore).toBe(0);
      expect(result.signals).toHaveLength(0);
    });
  });
});
