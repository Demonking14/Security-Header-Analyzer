import { Finding } from "../types";


const VALID_VALUE = "nosniff";

function classifyXcto(rawHeader: string | null | undefined):"missing" | "valid" | "malformed"{
    if(rawHeader==null)return "missing";
    const trimmed = rawHeader.trim();
    if(trimmed === "")return "missing";
    return trimmed.toLowerCase() === VALID_VALUE ? "valid" : "malformed";
}
function finding(
    id:string,
    status:Finding["status"],
    points:number,
    reason:string
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
export function analyzeContentTypeOptions(rawHeader: string | null | undefined):Finding{
    const cts = classifyXcto(rawHeader);
    if(cts == 'missing'){
        return finding(
            'xcto-0',
            "missing",
            0,
            'X-content-Type-Options header is missing; browsers may MIME-sniff responses'
        );
    }
    if(cts ==='valid'){
        return finding(
            'xcto-1',
            "strong",
            10,
            "X-Content-Type-Options: nosniff disables MIME sniffing"
        )
    }
    return finding(
        "xcto-2",
        "malformed",
        0,
        `X-Content-Type-Options has an unrecognized value (${JSON.stringify(rawHeader)}); only "nosniff" is valid, and it must be the entire value`
    )

}