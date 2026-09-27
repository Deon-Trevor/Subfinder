import {
  NAMEPREP_B1_RANGES,
  NAMEPREP_B2_MAP,
  NAMEPREP_LCAT_RANGES,
  NAMEPREP_PROHIBITED_RANGES,
  NAMEPREP_RANDAL_RANGES,
  PSL_EXCEPTION_RULES,
  PSL_EXACT_RULES,
  PSL_SHA256,
  PSL_WILDCARD_RULES,
  PYTHON_LOWER_MAP,
  PYTHON_WHITESPACE_RANGES,
  UNICODE_3_2_UNASSIGNED_RANGES,
} from "./generated/domain-policy-data.js";


export { PSL_SHA256 };
export const DOMAIN_POLICY_VERSION = `python-idna2003+psl-${PSL_SHA256}`;

const exactRules = new Set(PSL_EXACT_RULES);
const wildcardRules = new Set(PSL_WILDCARD_RULES);
const exceptionRules = new Set(PSL_EXCEPTION_RULES);
const lowerMap = new Map(PYTHON_LOWER_MAP);
const nameprepB2 = new Map(NAMEPREP_B2_MAP);
const labelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;


function inRanges(value, ranges) {
  let low = 0;
  let high = ranges.length - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const [start, end] = ranges[middle];
    if (value < start) high = middle - 1;
    else if (value > end) low = middle + 1;
    else return true;
  }
  return false;
}


function mapCodePoints(value, mapping) {
  let result = "";
  for (const character of value) {
    result += mapping.get(character.codePointAt(0)) ?? character;
  }
  return result;
}


function pythonStrip(value) {
  const characters = [...value];
  let start = 0;
  let end = characters.length;
  while (
    start < end &&
    inRanges(characters[start].codePointAt(0), PYTHON_WHITESPACE_RANGES)
  ) start += 1;
  while (
    end > start &&
    inRanges(characters[end - 1].codePointAt(0), PYTHON_WHITESPACE_RANGES)
  ) end -= 1;
  return characters.slice(start, end).join("");
}


function normalizeUnicode32(value) {
  let result = "";
  let assigned = "";
  const flush = () => {
    result += assigned.normalize("NFKC");
    assigned = "";
  };
  for (const character of value) {
    if (
      inRanges(character.codePointAt(0), UNICODE_3_2_UNASSIGNED_RANGES)
    ) {
      flush();
      result += character;
    } else {
      assigned += character;
    }
  }
  flush();
  return result;
}


function nameprep(label) {
  let mapped = "";
  for (const character of label) {
    const value = character.codePointAt(0);
    if (!inRanges(value, NAMEPREP_B1_RANGES)) {
      mapped += nameprepB2.get(value) ?? character;
    }
  }
  const normalized = normalizeUnicode32(mapped);
  for (const character of normalized) {
    if (inRanges(character.codePointAt(0), NAMEPREP_PROHIBITED_RANGES)) {
      throw new Error("apex must be a valid eTLD+1");
    }
  }
  const characters = [...normalized];
  const hasRandAL = characters.some((character) =>
    inRanges(character.codePointAt(0), NAMEPREP_RANDAL_RANGES));
  if (hasRandAL) {
    if (characters.some((character) =>
      inRanges(character.codePointAt(0), NAMEPREP_LCAT_RANGES))) {
      throw new Error("apex must be a valid eTLD+1");
    }
    if (
      !inRanges(characters[0].codePointAt(0), NAMEPREP_RANDAL_RANGES) ||
      !inRanges(characters.at(-1).codePointAt(0), NAMEPREP_RANDAL_RANGES)
    ) {
      throw new Error("apex must be a valid eTLD+1");
    }
  }
  return normalized;
}


function punycodeDigit(value) {
  return String.fromCharCode(value + (value < 26 ? 97 : 22));
}


function adaptBias(delta, points, first) {
  delta = first ? Math.floor(delta / 700) : delta >> 1;
  delta += Math.floor(delta / points);
  let k = 0;
  while (delta > 455) {
    delta = Math.floor(delta / 35);
    k += 36;
  }
  return k + Math.floor((36 * delta) / (delta + 38));
}


function encodePunycode(value) {
  const input = [...value].map((character) => character.codePointAt(0));
  const output = input
    .filter((point) => point < 0x80)
    .map((point) => String.fromCharCode(point));
  const basic = output.length;
  let handled = basic;
  if (basic > 0) output.push("-");
  let n = 128;
  let delta = 0;
  let bias = 72;
  while (handled < input.length) {
    const next = Math.min(...input.filter((point) => point >= n));
    delta += (next - n) * (handled + 1);
    n = next;
    for (const point of input) {
      if (point < n) delta += 1;
      if (point !== n) continue;
      let q = delta;
      for (let k = 36; ; k += 36) {
        const threshold = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
        if (q < threshold) break;
        output.push(punycodeDigit(threshold + ((q - threshold) % (36 - threshold))));
        q = Math.floor((q - threshold) / (36 - threshold));
      }
      output.push(punycodeDigit(q));
      bias = adaptBias(delta, handled + 1, handled === basic);
      delta = 0;
      handled += 1;
    }
    delta += 1;
    n += 1;
  }
  return output.join("");
}


function toAsciiLabel(label) {
  if (/^[\x00-\x7f]+$/.test(label)) {
    if (label.length < 64) return label;
    throw new Error("apex must be a valid eTLD+1");
  }
  const prepared = nameprep(label);
  if (/^[\x00-\x7f]+$/.test(prepared)) {
    if (prepared.length > 0 && prepared.length < 64) return prepared;
    throw new Error("apex must be a valid eTLD+1");
  }
  if (prepared.startsWith("xn--")) {
    throw new Error("apex must be a valid eTLD+1");
  }
  const encoded = `xn--${encodePunycode(prepared)}`;
  if (encoded.length > 0 && encoded.length < 64) return encoded;
  throw new Error("apex must be a valid eTLD+1");
}


function idnaToAscii(value) {
  if (/^[\x00-\x7f]*$/.test(value)) {
    const labels = value.split(".");
    for (const label of labels.slice(0, -1)) {
      if (label.length === 0 || label.length >= 64) {
        throw new Error("apex must be a valid eTLD+1");
      }
    }
    if (labels.at(-1).length >= 64) {
      throw new Error("apex must be a valid eTLD+1");
    }
    return value;
  }
  const labels = value.split(/[.\u3002\uff0e\uff61]/u);
  const trailingDot = labels.length > 0 && labels.at(-1) === "";
  if (trailingDot) labels.pop();
  return labels.map(toAsciiLabel).join(".") + (trailingDot ? "." : "");
}


function publicSuffixLength(labels) {
  for (let offset = 0; offset < labels.length; offset += 1) {
    const candidate = labels.slice(offset).join(".");
    if (exceptionRules.has(candidate)) return labels.length - offset - 1;
  }
  let longest = 0;
  for (let offset = 0; offset < labels.length; offset += 1) {
    const candidate = labels.slice(offset).join(".");
    if (exactRules.has(candidate)) {
      longest = Math.max(longest, labels.length - offset);
    }
    if (offset > 0 && wildcardRules.has(candidate)) {
      longest = Math.max(longest, labels.length - offset + 1);
    }
  }
  return longest;
}


export function normalizeApex(value) {
  let candidate;
  try {
    if (
      typeof value !== "string" ||
      mapCodePoints(pythonStrip(value), lowerMap).replace(/\.+$/, "").startsWith("*.")
    ) {
      throw new Error("wildcard apex");
    }
    candidate = normalizeHostname(value);
  } catch {
    throw new Error("apex must be a valid eTLD+1");
  }
  const labels = candidate.split(".");
  const suffixLength = publicSuffixLength(labels);
  if (suffixLength === 0 || labels.length <= suffixLength) {
    throw new Error("apex must be a valid eTLD+1");
  }
  if (labels.length !== suffixLength + 1) {
    throw new Error("apex must be an eTLD+1");
  }
  return candidate;
}


export function normalizeHostname(value) {
  if (typeof value !== "string") throw new Error("hostname is invalid");
  let candidate = mapCodePoints(pythonStrip(value), lowerMap).replace(/\.+$/, "");
  if (candidate.startsWith("*.")) candidate = candidate.slice(2);
  candidate = idnaToAscii(candidate);
  const labels = candidate.split(".");
  if (
    candidate.length > 253 ||
    labels.length < 2 ||
    labels.some((label) => !labelPattern.test(label))
  ) {
    throw new Error("hostname is invalid");
  }
  return candidate;
}


export function apexForHostname(value) {
  const hostname = normalizeHostname(value);
  const labels = hostname.split(".");
  const suffixLength = publicSuffixLength(labels);
  if (suffixLength === 0 || labels.length <= suffixLength) return hostname;
  return labels.slice(-(suffixLength + 1)).join(".");
}


export function zoneForApex(apex) {
  const labels = apex.split(".");
  const suffixLength = publicSuffixLength(labels);
  if (suffixLength === 0) throw new Error("apex must have a public suffix");
  return labels.slice(-suffixLength).join(".");
}
