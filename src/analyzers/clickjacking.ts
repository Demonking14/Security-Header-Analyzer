import { Finding } from "../types";
import { classifyXfo } from "./frameOptions";
type FrameAncestors = | { kind: 'absent' } | { kind: 'none' } | { kind: 'self' } | { kind: 'wildcard' } | { kind: 'list'; sources: string[] } | { kind: "malformed"; raw: string };

export function getFrameAncestors(rawCsp: string | null | undefined): FrameAncestors {
    if (rawCsp == null) return { kind: 'absent' };
    for (const directive of rawCsp.split(';')) {
        const trimmed = directive.trim();
        if (trimmed === "") continue;

        const firstWs = trimmed.search(/\s/);
        const name = (firstWs === -1 ? trimmed : trimmed.slice(0, firstWs)).toLowerCase();
        if (name !== 'frame-ancestors') continue;
        const rest = firstWs === -1 ? "" : trimmed.slice(firstWs + 1).trim();
        if (rest === "") return { kind: 'malformed', raw: trimmed };
        const sources = rest.split(/\s+/);
        if (sources.length === 1) {
            const only = sources[0].toLowerCase();
            if (only === "'none'") return { kind: 'none' };
            if (only === "'self'") return { kind: "self" };
            if (sources[0] === '*') return { kind: 'wildcard' };
        }
        return { kind: 'list', sources };
    }
    return { kind: "absent" };
}

type Protection = | { level: 'none' } | { level: 'restricted'; strength: number };

function xfoProtection(xfo: ReturnType<typeof classifyXfo>): Protection {
    switch (xfo) {
        case 'deny': return { level: 'restricted', strength: 10 };
        case 'sameorigin': return { level: 'restricted', strength: 8 };
        case 'missing':
        case 'malformed':
        default:
            return { level: 'none' };
    }
}


function cspProtection(fa: FrameAncestors): Protection {
    switch (fa.kind) {
        case "none": return { level: 'restricted', strength: 10 };
        case 'self': return { level: 'restricted', strength: 10 };
        case 'wildcard': return { level: 'none' }
        case 'list': return { level: 'restricted', strength: 9 };
        case "malformed":
        case "absent":
        default:
            return { level: 'none' };
    }
}

function protectionRank(p: Protection): number {
    return p.level === "none" ? -1 : p.strength;
}
function weaker(a: Protection, b: Protection): Protection {
    return protectionRank(a) <= protectionRank(b) ? a : b;
}

function finding(
    id: string,
    status: Finding['status'],
    points: number,
    reason: string,
): Finding {
    return { id, category: 'header', kind: "grade", status, points, reason };
}
function describeXfo(xfo: ReturnType<typeof classifyXfo>): string {
    switch (xfo) {
        case "deny": return "DENY";
        case "sameorigin": return "SAMEORIGIN";
        case "missing": return "absent";
        case "malformed": return "malformed";
    }
}
function describeFa(fa: FrameAncestors): string {
    switch (fa.kind) {
        case "absent": return "absent";
        case "none": return "'none'";
        case "self": return "'self'";
        case "wildcard": return "*";
        case "list": return `allowlisted (${fa.sources.join(" ")})`;
        case "malformed": return `malformed (${JSON.stringify(fa.raw)})`;
    }
}

function buildNoneReason(
    xfo: ReturnType<typeof classifyXfo>,
    fa: FrameAncestors
): string {
    if (fa.kind === "wildcard") {
        return `CSP frame-ancestors * explicitly allows framing from any origin, and X-Frame-Options is ${describeXfo(xfo)}; the page is clickjackable`;
    }
    if (xfo === 'missing' && fa.kind === 'absent') {
        return "Neither X-Frame-Options nor CSP frame-ancestors is set; the page is clickjackable"
    }
    return `No effective framing restriction: X-Frame-Options is ${describeXfo(xfo)} and CSP frame-ancestors is ${describeFa(fa)}`
}

function buildBothReason(
    xfo: ReturnType<typeof classifyXfo>,
    fa: FrameAncestors,
): string {
    if (fa.kind === "absent") {
        return `X-Frame-Options ${describeXfo(xfo)} restricts framing; no CSP frame-ancestors present, so both modern and legacy browsers fall back to XFO`
    }
    return `Both X-Frame-Options ${describeXfo(xfo)} and CSP frame-ancestors ${describeFa(fa)} restrict framing; modern browsers honor CSP, legacy browsers honor XFO, and both are protected`;
}

export function analyzeClickjackingProtection(
    rawXfo: string | null | undefined,
    rawCsp: string | null | undefined
): Finding {
    const xfo = classifyXfo(rawXfo);
    const fa = getFrameAncestors(rawCsp);

    const legacyProtection = xfoProtection(xfo);
    const modernProtection = fa.kind === "absent" ? xfoProtection(xfo) : cspProtection(fa);
    const effective = weaker(modernProtection, legacyProtection);
    if (effective.level == 'none') {
        return finding(
            'cj-0',
            'missing',
            0,
            buildNoneReason(xfo, fa)
        )
    }
    if (protectionRank(modernProtection) < protectionRank(legacyProtection)) {
        return finding(
            'cj-1',
            'weak',
            0,
            `Modern browsers can frame this page: CSP frame-ancestors ${describeFa(fa)} overrides X-Frame-Options ${describeXfo(xfo)}. Legacy browsers are protected by XFO, but the modern web is exposed to clickjacking`,
        )
    }
    if (protectionRank(legacyProtection) < protectionRank(modernProtection)) {
        return finding(
            "cj-2",
            "weak",
            0,
            `Legacy browsers can frame this page: CSP frame-ancestors ${describeFa(fa)} protects modern browsers, but X-Frame-Options is ${describeXfo(xfo)}, so pre-CSP browsers (IE11, old Safari) are exposed to clickjacking`,
        )
    }
    const strength = protectionRank(effective);
    const status = strength >= 8 ? "strong" : "weak";
    return finding(
        'cj-3',
        status,
        strength,
        buildBothReason(xfo, fa),
    );
}


function buildCleanReason(
    xfo: ReturnType<typeof classifyXfo>,
    fa: FrameAncestors
): string {
    if (xfo === "missing" && fa.kind === "absent") {
        return "Neither X-Frame-Options nor CSP frame-ancestors is set (common, not suspicious).";
    }
    if (fa.kind === "absent") {
        return `X-Frame-Option is ${describeXfo(xfo)}; no CSP frame-ancestors present`;
    }
    return `X-Frame-Options is ${describeXfo(xfo)} and CSP frame-ancestors is ${describeFa(fa)}; no wildcard framing allowed`;
}

function anomaly(
    id: string,
    status: Finding['status'],
    points: number,
    reason: string
): Finding {
    return {
        id, category: 'header', kind: 'anomaly', points, reason, status
    }
}

export function analyzeClickjackingAnomaly(
    rawXfo: string | null | undefined,
    rawCsp: string | null | undefined
): Finding {
    const xfo = classifyXfo(rawXfo);
    const fa = getFrameAncestors(rawCsp);

    const XfoIsStrict = xfo === 'deny' || xfo === 'sameorigin';
    const cspIsWildcard = fa.kind === "wildcard";

    if (!XfoIsStrict && !cspIsWildcard && fa.kind === "absent" && xfo === "missing") {
        return anomaly(
            'cj-anom-0',
            'informational',
            0,
            "Neither X-Frame-Options nor CSP frame-ancestors is set; absence of clickjacking defenses is too common to be suspicious",
        )
    }
    if (XfoIsStrict && cspIsWildcard) {
        return anomaly(
            "cj-anom-1",
            "suspicious",
            10,
            `X-Frame-Options is ${describeXfo(xfo)} but CSP frame-ancestors is *, which overrides it in modern browsers; this contradiction suggests misconfiguration or tampering`
        )
    }
    if (cspIsWildcard) {
        return anomaly(
            "cj-anom-2",
            "suspicious",
            5,
            `CSP frame-ancestors is *, allowing the page to be framed from any origin; known phishing vector`,
        );
    }

    // ---- 4. Everything else → benign ----
    return anomaly(
        "cj-anom-3",
        "informational",
        0,
        buildCleanReason(xfo, fa),
    );
}