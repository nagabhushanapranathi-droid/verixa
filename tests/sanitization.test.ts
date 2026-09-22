import { describe, it, expect } from "vitest";
import { sanitizeTextInput, sanitizeBase64Image } from "@/lib/sanitization";

describe("Input Sanitization Engine: sanitizeTextInput & sanitizeBase64Image", () => {
  describe("sanitizeTextInput", () => {
    it("accepts and trims normal corporate text input", () => {
      const input = "   Dear Candidate, congratulations on your offer with Acme Corp!   \n\n";
      const result = sanitizeTextInput(input);

      expect(result.isValid).toBe(true);
      expect(result.sanitized).toBe("Dear Candidate, congratulations on your offer with Acme Corp!");
      expect(result.charCount).toBe("Dear Candidate, congratulations on your offer with Acme Corp!".length);
      expect(result.error).toBeUndefined();
    });

    it("rejects non-string inputs cleanly without throwing", () => {
      expect(sanitizeTextInput(null).isValid).toBe(false);
      expect(sanitizeTextInput(undefined).isValid).toBe(false);
      expect(sanitizeTextInput(12345).isValid).toBe(false);
      expect(sanitizeTextInput({ text: "hello" }).isValid).toBe(false);
      expect(sanitizeTextInput([]).isValid).toBe(false);
    });

    it("rejects empty or whitespace-only strings", () => {
      expect(sanitizeTextInput("").isValid).toBe(false);
      expect(sanitizeTextInput("    \n\t   ").isValid).toBe(false);
      expect(sanitizeTextInput("").error).toContain("cannot be empty");
    });

    it("strips null bytes (\\0) and malicious non-printable control characters", () => {
      const malicious = "Job Offer\0\x01\x02 from\x03\x04 Google\x05";
      const result = sanitizeTextInput(malicious);

      expect(result.isValid).toBe(true);
      expect(result.sanitized).toBe("Job Offer from Google");
    });

    it("preserves legitimate newlines and formatting", () => {
      const formatted = "Line 1: Salary: $120,000\nLine 2: Location: Remote\r\nLine 3: Start: Next Monday";
      const result = sanitizeTextInput(formatted);

      expect(result.isValid).toBe(true);
      expect(result.sanitized).toContain("Line 1");
      expect(result.sanitized).toContain("Line 2");
      expect(result.sanitized).toContain("Line 3");
    });

    it("enforces custom maximum length bounds", () => {
      const longText = "A".repeat(100);
      const result = sanitizeTextInput(longText, 50);

      expect(result.isValid).toBe(false);
      expect(result.charCount).toBe(100);
      expect(result.sanitized).toBe("A".repeat(50));
      expect(result.error).toContain("exceeds maximum allowed length of 50");
    });
  });

  describe("sanitizeBase64Image", () => {
    it("handles valid data URI prefixed base64 image strings", () => {
      // 1x1 transparent PNG base64
      const validDataUri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";
      const result = sanitizeBase64Image(validDataUri);

      expect(result.isValid).toBe(true);
      expect(result.mimeType).toBe("image/png");
      expect(result.sanitized).toBe("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=");
      expect(result.estimatedSizeBytes).toBeGreaterThan(0);
    });

    it("handles raw base64 string without data URI prefix", () => {
      const rawBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";
      const result = sanitizeBase64Image(rawBase64);

      expect(result.isValid).toBe(true);
      expect(result.mimeType).toBeUndefined();
      expect(result.sanitized).toBe(rawBase64);
    });

    it("rejects non-string or empty image inputs", () => {
      expect(sanitizeBase64Image(null).isValid).toBe(false);
      expect(sanitizeBase64Image("").isValid).toBe(false);
      expect(sanitizeBase64Image("   ").isValid).toBe(false);
    });

    it("rejects invalid base64 characters", () => {
      const corrupt = "data:image/png;base64,NotABase64StringWithIllegalCharacters$$$!!!";
      const result = sanitizeBase64Image(corrupt);

      expect(result.isValid).toBe(false);
      expect(result.error).toContain("Invalid base64 encoding format");
    });

    it("enforces maximum image byte size limits", () => {
      // Create valid base64 payload larger than 50 bytes limit
      const bigPayload = Buffer.from("A".repeat(200)).toString("base64");
      const result = sanitizeBase64Image(bigPayload, 50);

      expect(result.isValid).toBe(false);
      expect(result.error).toContain("exceeds maximum limit");
    });
  });
});
