/**
 * Pure, stateless JSON parsing and entity extraction heuristics.
 * Recovers structured data from markdown wrappers, cleans malformed responses,
 * and extracts organizations, emails, phone numbers, and URLs without side effects.
 */

export interface ExtractedEntitiesData {
  companyName?: string;
  contactInfo?: string;
  urls?: string[];
}

/**
 * Strips markdown fences, quotes, and whitespace from model responses and parses JSON safely.
 * Returns fallback or throws informative error if fallback is not provided.
 */
export function cleanAndParseJson<T = any>(rawText: unknown, fallback?: T): T {
  if (typeof rawText !== "string") {
    if (fallback !== undefined) return fallback;
    throw new Error("Input must be a string to parse JSON.");
  }

  let cleaned = rawText.trim();

  // Strip markdown code fences: ```json ... ``` or ``` ... ```
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, "");
  cleaned = cleaned.replace(/\s*```$/i, "");
  cleaned = cleaned.trim();

  // Locate the first { and last } to avoid outer commentary
  const firstBrace = cleaned.indexOf("{");
  const lastBrace = cleaned.lastIndexOf("}");

  if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
    cleaned = cleaned.substring(firstBrace, lastBrace + 1);
  }

  try {
    return JSON.parse(cleaned) as T;
  } catch (err: any) {
    if (fallback !== undefined) {
      return fallback;
    }
    throw new Error(`Failed to parse JSON response: ${err?.message || "Invalid JSON format"}`);
  }
}

/**
 * Pure heuristic entity extraction to recover claimed organization names,
 * contact info (emails, phones, handles), and URLs from text.
 */
export function extractEntitiesFromText(
  text: string,
  existing?: ExtractedEntitiesData
): ExtractedEntitiesData {
  const result: ExtractedEntitiesData = {
    companyName: existing?.companyName,
    contactInfo: existing?.contactInfo,
    urls: existing?.urls ? [...existing.urls] : [],
  };

  if (!text || typeof text !== "string") {
    return result;
  }

  // 1. Recover URLs if missing
  if (!result.urls || result.urls.length === 0) {
    const urlMatches = text.match(/https?:\/\/[^\s"'<>]+/gi);
    if (urlMatches) {
      result.urls = Array.from(new Set(urlMatches));
    }
  }

  // 2. Recover contact info (emails, phones, telegram/whatsapp) if missing
  if (!result.contactInfo || result.contactInfo.trim().length === 0) {
    const emailMatches = text.match(/[\w.-]+@[\w.-]+\.\w+/gi);
    const phoneMatches = text.match(/(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g);
    
    // Match t.me links or @handles that are not email domains
    const tMeMatch = text.match(/(?:https?:\/\/)?(?:www\.)?t\.me\/([a-zA-Z0-9_]{5,32})/i);
    const atHandleMatch = text.match(/(?:^|\s)@([a-zA-Z0-9_]{5,32})(?!\.[a-zA-Z])/);

    const contacts: string[] = [];
    if (emailMatches) contacts.push(...emailMatches);
    if (phoneMatches) contacts.push(...phoneMatches);
    if (tMeMatch) {
      contacts.push(`Telegram: t.me/${tMeMatch[1]}`);
    } else if (atHandleMatch) {
      contacts.push(`Handle: @${atHandleMatch[1]}`);
    }

    if (contacts.length > 0) {
      result.contactInfo = Array.from(new Set(contacts)).join(", ");
    }
  }

  // 3. Recover company/entity name if omitted or generic
  const isGeneric =
    !result.companyName ||
    result.companyName.toLowerCase().includes("unspecified") ||
    result.companyName.toLowerCase().includes("none") ||
    result.companyName.toLowerCase().includes("unknown");

  if (isGeneric) {
    // Look for explicit prefix: "Company: X", "Employer: X", "Organization: X"
    const explicitMatch = text.match(/(?:Company|Organization|Firm|Employer):\s*([A-Za-z0-9&.\s]{2,35})(?:\n|\r|$|,|\.)/i);
    if (explicitMatch && explicitMatch[1]) {
      result.companyName = explicitMatch[1].trim();
    } else {
      // Look for natural phrases: "at Google", "team at Amazon", "joining Microsoft Corporation"
      // Stop before lowercase conjunctions/prepositions like " as ", " for ", " in ", " with "
      const phraseMatch = text.match(/(?:offer from|careers at|HR at|team at|joining|welcome to)\s+([A-Z][A-Za-z0-9&.]*(?:\s+[A-Z][A-Za-z0-9&.]*)*)/);
      if (phraseMatch && phraseMatch[1]) {
        result.companyName = phraseMatch[1].trim();
      }
    }
  }

  return result;
}
