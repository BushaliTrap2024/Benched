import {readFileSync} from "node:fs";
// Verbatim V1 functions from pinned upstream; see UPSTREAM.json and LICENSE.upstream.
export function scoreFindVulns(
  findingsInput: FindingsInput,
  task: EvalTask,
): FindVulnsDetails {
  const agentFindings = parseFindings(findingsInput);
  const knownVulns = task.knownVulns;

  const truePositives: VulnMatch[] = [];
  const matchedKnownIds = new Set<string>();
  const matchedFindingIdxs = new Set<number>();

  for (let i = 0; i < agentFindings.length; i++) {
    const found = agentFindings[i];
    const match = knownVulns.find(
      (kv) => !matchedKnownIds.has(kv.id) && vulnTypesMatch(kv.type, found.type),
    );
    if (match) {
      truePositives.push({ id: match.id, type: match.type, severity: match.severity });
      matchedKnownIds.add(match.id);
      matchedFindingIdxs.add(i);
    }
  }

  const falsePositives = agentFindings.filter((_, i) => !matchedFindingIdxs.has(i));
  const falseNegatives: VulnMatch[] = knownVulns
    .filter((kv) => !matchedKnownIds.has(kv.id))
    .map((kv) => ({ id: kv.id, type: kv.type, severity: kv.severity }));

  const precision = agentFindings.length === 0 ? 0 : truePositives.length / agentFindings.length;
  const recall = knownVulns.length === 0 ? 1 : truePositives.length / knownVulns.length;

  const byType = computeBreakdown(knownVulns, truePositives, falsePositives, (v) => v.type);
  const bySeverity = computeBreakdown(knownVulns, truePositives, falsePositives, (v) => v.severity);

  return { agentFindings, truePositives, falsePositives, falseNegatives, precision, recall, byType, bySeverity };
}


function computeBreakdown(
  knownVulns: Vulnerability[],
  truePositives: VulnMatch[],
  falsePositives: Vulnerability[],
  keyFn: (v: { type: VulnType; severity: Severity }) => string,
): Record<string, BreakdownEntry> {
  const result: Record<string, BreakdownEntry> = {};

  const totalByKey = new Map<string, number>();
  for (const kv of knownVulns) {
    const key = keyFn(kv);
    totalByKey.set(key, (totalByKey.get(key) ?? 0) + 1);
  }

  const foundByKey = new Map<string, number>();
  for (const tp of truePositives) {
    const key = keyFn(tp);
    foundByKey.set(key, (foundByKey.get(key) ?? 0) + 1);
  }

  const fpByKey = new Map<string, number>();
  for (const fp of falsePositives) {
    const key = keyFn(fp);
    fpByKey.set(key, (fpByKey.get(key) ?? 0) + 1);
  }

  const allKeys = new Set([...totalByKey.keys(), ...fpByKey.keys()]);
  for (const key of allKeys) {
    const total = totalByKey.get(key) ?? 0;
    const found = foundByKey.get(key) ?? 0;
    const fp = fpByKey.get(key) ?? 0;
    const recall = total === 0 ? 0 : found / total;
    const prec = (found + fp) === 0 ? 0 : found / (found + fp);
    result[key] = { total, found, precision: prec, recall, f1: f1(prec, recall) };
  }

  return result;
}


function parseFindings(input: FindingsInput): Vulnerability[] {
  if (typeof input !== "string") {
    return normalizeFindings([...input]);
  }
  const output = input;
  // Look for a JSON block after FINDINGS_JSON: marker
  const marker = /FINDINGS_JSON:\s*```(?:json)?\s*([\s\S]*?)```/i;
  const match = output.match(marker);
  if (!match) {
    // Fall back to any JSON array in the output
    const arrayMatch = output.match(/\[[\s\S]*?\]/);
    if (!arrayMatch) return [];
    try {
      return normalizeFindings(JSON.parse(arrayMatch[0]));
    } catch {
      return [];
    }
  }
  try {
    return normalizeFindings(JSON.parse(match[1]));
  } catch {
    return [];
  }
}


function normalizeFindings(raw: unknown[]): Vulnerability[] {
  return raw
    .filter((item): item is Record<string, unknown> => typeof item === "object" && item !== null)
    .map((item, idx) => ({
      id: `found-${idx}`,
      type: normalizeVulnType(String(item.type ?? "other")),
      severity: normalizeSeverity(String(item.severity ?? "medium")),
      file: String(item.file ?? ""),
      line: typeof item.line === "number" ? item.line : undefined,
      description: String(item.description ?? ""),
    }));
}

function normalizeVulnType(raw: string): VulnType {
  const map: Record<string, VulnType> = {
    "sql injection": "sql-injection",
    "sql-injection": "sql-injection",
    "sqli": "sql-injection",
    "cross-site scripting": "xss",
    "xss": "xss",
    "dom xss": "xss",
    "dom-xss": "xss",
    "dom based xss": "xss",
    "path traversal": "path-traversal",
    "path-traversal": "path-traversal",
    "directory traversal": "path-traversal",
    "command injection": "command-injection",
    "command-injection": "command-injection",
    "rce": "command-injection",
    "code injection": "code-injection",
    "code-injection": "code-injection",
    "eval injection": "code-injection",
    "mass assignment": "mass-assignment",
    "mass-assignment": "mass-assignment",
    "template injection": "template-injection",
    "template-injection": "template-injection",
    "hardcoded credentials": "hardcoded-credentials",
    "hardcoded-credentials": "hardcoded-credentials",
    "hardcoded secret": "hardcoded-credentials",
    "hardcoded non-cryptographic secret": "hardcoded-credentials",
    "hardcoded-non-cryptographic-secret": "hardcoded-credentials",
    "insecure deserialization": "insecure-deserialization",
    "insecure-deserialization": "insecure-deserialization",
    "idor": "idor",
    "broken object level authorization": "idor",
    "xxe": "xxe",
    "xml external entity": "xxe",
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "server side request forgery": "ssrf",
    "open redirect": "open-redirect",
    "open-redirect": "open-redirect",
    "csrf": "csrf",
    "cross-site request forgery": "csrf",
    "cross site request forgery": "csrf",
    "information-exposure": "information-exposure",
    "information exposure": "information-exposure",
    "information disclosure": "information-exposure",
    "info leak": "information-exposure",
    "sensitive data exposure": "information-exposure",
    "allocation-of-resources-without-limits-or-throttling": "allocation-of-resources-without-limits-or-throttling",
    "allocation-of-resources-without-limits": "allocation-of-resources-without-limits-or-throttling",
    "allocation of resources without limits or throttling": "allocation-of-resources-without-limits-or-throttling",
    "missing rate limiting": "allocation-of-resources-without-limits-or-throttling",
    "no rate limit": "allocation-of-resources-without-limits-or-throttling",
    "resource exhaustion": "allocation-of-resources-without-limits-or-throttling",
    "denial of service": "allocation-of-resources-without-limits-or-throttling",
    "dos": "allocation-of-resources-without-limits-or-throttling",
    "redos": "redos",
    "redospolynomial": "redos",
    "regular expression denial of service": "redos",
    "regular-expression-denial-of-service": "redos",
    "polynomial regular expression denial of service": "redos",
    "improper code sanitization": "improper-code-sanitization",
    "improper-code-sanitization": "improper-code-sanitization",
    "code injection through eval": "improper-code-sanitization",
    "unsafe eval": "improper-code-sanitization",
    "improper type validation": "improper-type-validation",
    "improper-type-validation": "improper-type-validation",
    "type confusion": "improper-type-validation",
    "insecure transport": "insecure-transport",
    "insecure-transport": "insecure-transport",
    "cleartext transmission": "insecure-transport",
    "cleartext-transmission": "insecure-transport",
    "http to https": "insecure-transport",
    "http-to-https": "insecure-transport",
    "insecure cryptography": "insecure-cryptography",
    "insecure-cryptography": "insecure-cryptography",
    "insecure cipher": "insecure-cryptography",
    "weak cryptography": "insecure-cryptography",
    "weak-cryptography": "insecure-cryptography",
    "weak cipher": "insecure-cryptography",
    "broken cryptographic algorithm": "insecure-cryptography",
    "risky cryptographic algorithm": "insecure-cryptography",
    "sensitive cookie with secure flag false": "information-exposure",
    "sensitive-cookie-with-secure-flag-false": "information-exposure",
    "insecure cookie": "information-exposure",
    "missing secure cookie": "information-exposure",
    "prototype pollution": "prototype-pollution",
    "prototype-pollution": "prototype-pollution",
    "prototype pollution vulnerability": "prototype-pollution",
    "origin validation error": "origin-validation-error",
    "origin-validation-error": "origin-validation-error",
    "cors misconfiguration": "origin-validation-error",
    "permissive cors": "origin-validation-error",
    "insecure cors": "origin-validation-error",
    "too permissive cors": "origin-validation-error",
    "overly permissive cors": "origin-validation-error",
    "other": "other",
  };
  const key = raw.toLowerCase().trim();
  return map[key] ?? "other";
}

function normalizeSeverity(raw: string): Severity {
  const s = raw.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "low") return "low";
  return "medium";
}

function vulnTypesMatch(known: VulnType, found: VulnType): boolean {
  if (known === found) return true;
  // Allow "other" to match anything as a fallback
  if (found === "other") return false;
  return false;
}


function f1(p:number,r:number){return p+r===0?0:2*p*r/(p+r)}
const input=JSON.parse(readFileSync(0,"utf8")); console.log(JSON.stringify(scoreFindVulns(input.findings,{knownVulns:input.known})));
