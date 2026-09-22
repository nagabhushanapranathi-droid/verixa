import { describe, it, expect } from "vitest";
import { cleanAndParseJson, extractEntitiesFromText } from "@/lib/json-parser";

describe("JSON Parser & Forensic Entity Recovery: json-parser", () => {
  describe("cleanAndParseJson", () => {
    it("parses clean JSON objects directly", () => {
      const jsonStr = '{"summary": "Test summary", "scamThreatIndex": 15}';
      const parsed = cleanAndParseJson<{ summary: string; scamThreatIndex: number }>(jsonStr);

      expect(parsed.summary).toBe("Test summary");
      expect(parsed.scamThreatIndex).toBe(15);
    });

    it("strips markdown json fences (```json ... ```)", () => {
      const wrapped = "```json\n{\n  \"status\": \"success\",\n  \"confidence\": 0.95\n}\n```";
      const parsed = cleanAndParseJson<{ status: string; confidence: number }>(wrapped);

      expect(parsed.status).toBe("success");
      expect(parsed.confidence).toBe(0.95);
    });

    it("strips raw markdown fences without language tag (``` ... ```)", () => {
      const wrapped = "```\n{\n  \"isScam\": false\n}\n```";
      const parsed = cleanAndParseJson<{ isScam: boolean }>(wrapped);

      expect(parsed.isScam).toBe(false);
    });

    it("extracts inner JSON when model adds preamble or trailing commentary", () => {
      const conversational = `Here is your security analysis report:
{
  "summary": "Urgent crypto payment request detected",
  "paymentRequests": true
}
Hope this helps keep you safe!`;

      const parsed = cleanAndParseJson<{ summary: string; paymentRequests: boolean }>(conversational);
      expect(parsed.summary).toBe("Urgent crypto payment request detected");
      expect(parsed.paymentRequests).toBe(true);
    });

    it("returns provided fallback on malformed JSON without throwing", () => {
      const brokenJson = "{ this is not valid json : 123 }";
      const fallback = { summary: "fallback", riskSignals: [] };
      const parsed = cleanAndParseJson(brokenJson, fallback);

      expect(parsed).toEqual(fallback);
    });

    it("throws informative error on malformed JSON when no fallback provided", () => {
      const brokenJson = "Definitely not JSON";
      expect(() => cleanAndParseJson(brokenJson)).toThrow("Failed to parse JSON response");
    });
  });

  describe("extractEntitiesFromText", () => {
    it("extracts company name from explicit keywords (Company: Acme)", () => {
      const text = "Company: Horizon Technologies Ltd.\nPosition: Junior Analyst\nSalary: $80,000";
      const entities = extractEntitiesFromText(text);

      expect(entities.companyName).toBe("Horizon Technologies Ltd.");
    });

    it("extracts company name from natural phrasing ('welcome to Google')", () => {
      const text = "We are pleased to extend this offer for joining Microsoft Corporation as a Senior Engineer.";
      const entities = extractEntitiesFromText(text);

      expect(entities.companyName).toBe("Microsoft Corporation");
    });

    it("extracts email addresses and phone numbers into contactInfo", () => {
      const text = "Please reach out to our recruiter at recruiter.john@acme-careers.com or call +1 415-555-0199.";
      const entities = extractEntitiesFromText(text);

      expect(entities.contactInfo).toContain("recruiter.john@acme-careers.com");
      expect(entities.contactInfo).toContain("415-555-0199");
    });

    it("extracts Telegram handles from recruitment lures", () => {
      const text = "Interview will be held online. Connect immediately with HR manager via t.me/recruiter_sarah.";
      const entities = extractEntitiesFromText(text);

      expect(entities.contactInfo).toContain("Telegram: t.me/recruiter_sarah");
    });

    it("extracts URLs from correspondence text", () => {
      const text = "Fill out onboarding forms at https://careers-portal.fakecompany.net/onboard before tomorrow.";
      const entities = extractEntitiesFromText(text);

      expect(entities.urls).toContain("https://careers-portal.fakecompany.net/onboard");
    });

    it("preserves already extracted entities when provided", () => {
      const text = "Contact hr@example.com for more info.";
      const existing = {
        companyName: "Pre-existing Corp",
        contactInfo: "pre-existing@phone.com",
        urls: ["https://existing.com"],
      };
      const entities = extractEntitiesFromText(text, existing);

      expect(entities.companyName).toBe("Pre-existing Corp");
      expect(entities.contactInfo).toBe("pre-existing@phone.com");
      expect(entities.urls).toContain("https://existing.com");
    });
  });
});
