import { Finding } from "../types";

function finding(
    id:string,
    status:Finding['status'],
    points:number,
    reason : string
):Finding{
    return {
        id,
        category:'header',
        kind:'grade',
        status,
        points,
        reason
    }
}


export function classifyXfo(
    rawHeader: string | null | undefined
):"missing"| "deny"| "sameorigin" |"malformed"{
    if(rawHeader == null)return "missing";
    const trimmed = rawHeader.trim();
    if(trimmed =="")return "missing";
    const lowered = trimmed.toLowerCase();
    if(lowered == "deny")return "deny";
    if(lowered == "sameorigin")return "sameorigin";
    return "malformed";
}

export function analyzeXFrameOptions(
    rawHeader:string | null | undefined,
):Finding{
    const cls = classifyXfo(rawHeader);
    if(cls == "missing"){
        return finding('xfo-0' , 'missing' , 0 , 'No X-Frame-Options header; page may be vulnerable to clickjacking');
    }
    if(cls == 'deny'){
        return finding('xfo-1' , 'strong' , 10 , 'X-Frame-Options: Deny forbids all framing (strictest possible)');
    }
    if(cls == 'sameorigin'){
        return finding(
            'xfo-2',
            'strong',
            8,
            'X-Frame-Options: SAMEORIGIN allows same-origin framing only; mitigates cross-origin clickjacking but is weaker than DENY'
        );
    }
    return finding(
        'xfo-3',
        'malformed',
        0,
        `X-Frame-Options has an unrecognized value (${JSON.stringify(rawHeader)}); only DENY or SAMEORIGIN are valid. Note: ALLOW-FROM is obsolete and ignored by modern browsers - use CSP frame-ancestors instead.`
    )
}