export interface SensitiveRule {
  word: string;
  level: 1 | 2 | 3;
  replacement?: string;
}

export const sensitiveRules: SensitiveRule[] = [];

export function filterSensitive(text: string): string {
  let result = text;
  for (const rule of sensitiveRules) {
    if (rule.level === 2 && rule.replacement) {
      result = result.replaceAll(rule.word, rule.replacement);
    }
    if (rule.level === 3 && result.includes(rule.word)) {
      throw new Error("Content blocked by security policy");
    }
  }
  return result;
}
