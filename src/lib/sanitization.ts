/**
 * Pure, stateless input sanitization and boundary validation utilities.
 * Completely decoupled from network, Next.js request objects, or external AI APIs.
 */

export interface TextSanitizationResult {
  isValid: boolean;
  sanitized: string;
  charCount: number;
  error?: string;
}

export interface ImageSanitizationResult {
  isValid: boolean;
  sanitized: string;
  mimeType?: string;
  estimatedSizeBytes: number;
  error?: string;
}

const DEFAULT_MAX_TEXT_LENGTH = 50000; // 50K characters
const DEFAULT_MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB

/**
 * Sanitizes and validates plain text input:
 * - Trims whitespace
 * - Strips dangerous null bytes (\0) and invisible control characters (except standard newlines/tabs)
 * - Checks length limits and empty content
 */
export function sanitizeTextInput(
  input: unknown,
  maxLength: number = DEFAULT_MAX_TEXT_LENGTH
): TextSanitizationResult {
  if (typeof input !== "string") {
    return {
      isValid: false,
      sanitized: "",
      charCount: 0,
      error: "Input must be a valid text string.",
    };
  }

  // Remove null bytes and non-printable control characters (except newline, return, tab)
  const cleaned = input
    .replace(/\0/g, "")
    // eslint-disable-next-line no-control-regex
    .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    .trim();

  if (cleaned.length === 0) {
    return {
      isValid: false,
      sanitized: "",
      charCount: 0,
      error: "Text content cannot be empty or solely whitespace.",
    };
  }

  if (cleaned.length > maxLength) {
    return {
      isValid: false,
      sanitized: cleaned.slice(0, maxLength),
      charCount: cleaned.length,
      error: `Text content exceeds maximum allowed length of ${maxLength} characters.`,
    };
  }

  return {
    isValid: true,
    sanitized: cleaned,
    charCount: cleaned.length,
  };
}

/**
 * Sanitizes and validates a base64 image string:
 * - Extracts mime type if data URI prefix is present (e.g. data:image/png;base64,...)
 * - Normalizes to raw base64 string
 * - Verifies base64 character set
 * - Estimates byte size and enforces upper limits
 */
export function sanitizeBase64Image(
  input: unknown,
  maxSizeBytes: number = DEFAULT_MAX_IMAGE_SIZE_BYTES
): ImageSanitizationResult {
  if (typeof input !== "string") {
    return {
      isValid: false,
      sanitized: "",
      estimatedSizeBytes: 0,
      error: "Image payload must be a base64-encoded string.",
    };
  }

  const trimmed = input.trim();
  if (trimmed.length === 0) {
    return {
      isValid: false,
      sanitized: "",
      estimatedSizeBytes: 0,
      error: "Image payload cannot be empty.",
    };
  }

  let mimeType: string | undefined;
  let rawBase64 = trimmed;

  const dataUriMatch = trimmed.match(/^data:(image\/[a-zA-Z0-9.+_-]+);base64,(.+)$/s);
  if (dataUriMatch) {
    mimeType = dataUriMatch[1];
    rawBase64 = dataUriMatch[2].trim();
  }

  // Basic base64 validation (alphanumeric, +, /, =, and optional newlines)
  const cleanBase64 = rawBase64.replace(/\s+/g, "");
  const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

  if (!base64Regex.test(cleanBase64) || cleanBase64.length === 0) {
    return {
      isValid: false,
      sanitized: "",
      estimatedSizeBytes: 0,
      error: "Invalid base64 encoding format.",
    };
  }

  // Calculate approximate byte size: (chars * 3) / 4 - padding
  const padding = (cleanBase64.endsWith("==") ? 2 : cleanBase64.endsWith("=") ? 1 : 0);
  const estimatedSizeBytes = Math.floor((cleanBase64.length * 3) / 4) - padding;

  if (estimatedSizeBytes > maxSizeBytes) {
    return {
      isValid: false,
      sanitized: "",
      mimeType,
      estimatedSizeBytes,
      error: `Image size (${Math.round(estimatedSizeBytes / 1024)}KB) exceeds maximum limit (${Math.round(maxSizeBytes / 1024)}KB).`,
    };
  }

  return {
    isValid: true,
    sanitized: cleanBase64,
    mimeType,
    estimatedSizeBytes,
  };
}
