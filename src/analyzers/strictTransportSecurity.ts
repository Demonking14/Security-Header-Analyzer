import { ParseDirective } from "./parseDirectives";
import { Finding } from "../types";

const ONE_YEAR = 3.1536e7;   //  31,536,000 seconds
const TWO_YEARS = 6.3072e7;   //  63,072,000 seconds
const TEN_YEARS = 10*365*86400; // 315,360,000 seconds
const RFC_MAX_AGE = 2**31-1;  //68 years


export function analyzeStrictTransportSecurity(
    rawHeader: string | null | undefined,
    parsed: ParseDirective,
): Finding {
    
    if (rawHeader == null || rawHeader.trim() === '') {
        return finding('0', 'missing', 0, 'Header missing');
    }

    if (!('max-age' in parsed)) {
        return finding(
            '1',
            'malformed',
            0,
            `Header is present ("${rawHeader}") but missing the required max-age directive; browsers ignore the whole header`,
        );
    }

    
    const maxAge = parsed['max-age'];
    if (typeof maxAge !== 'number') {
        return finding(
            '2',
            'malformed',
            0,
            `max-age must be an integer number of seconds, got ${JSON.stringify(maxAge)}`,
        );
    }

    if (maxAge < 0) {
        return finding('3', 'malformed', 0, `max-age cannot be negative, got ${maxAge}`);
    }

    if (maxAge === 0) {
        return finding('4', 'weak', 0, 'max-age is 0, which explicitly disables HSTS');
    }

    
    let base: number;
    if (maxAge >= TWO_YEARS) {
        base = 10;
    } else if (maxAge >= ONE_YEAR) {
        base = 8;
    } else {
        base = Math.floor((maxAge / ONE_YEAR) * 8);
    }

    
    const bonus =
        (parsed['includesubdomains'] === true ? 1 : 0) +
        (parsed['preload'] === true ? 1 : 0);


    const points = Math.min(base + bonus, 10);
    const status: Finding['status'] = points >= 8 ? 'strong' : 'weak';


    const reason = buildReason(maxAge, base, bonus, points, parsed);

    return finding('5', status, points, reason);
}

function buildReason(
    maxAge: number,
    base: number,
    bonus: number,
    points: number,
    parsed: ParseDirective,
): string {
    const ageText = humanize(maxAge);
    const missing = missingFlags(parsed);
    const missingText =
        missing.length === 0
            ? ''
            : missing.length === 1
                ? `; ${missing[0]} is missing`
                : `; ${missing.slice(0, -1).join(', ')} and ${missing[missing.length - 1]} are missing`;

    if (maxAge >= TWO_YEARS) {
        if (points === 10 && bonus === 2) {
            return `max-age is ${ageText}, with includeSubDomains and preload; meets the 2-year recommendation`;
        }
        return `max-age is ${ageText}, which meets the 2-year recommendation${missingText}`;
    }

    if (maxAge >= ONE_YEAR) {
        if (points === 10) {
            return `max-age is ${ageText}, with includeSubDomains and preload`;
        }
        return `max-age is ${ageText}, which is at least 1 year but below the 2-year recommendation (${humanize(TWO_YEARS)})${missingText}`;
    }

    return `max-age is ${ageText}, which is below the 1-year minimum (${humanize(ONE_YEAR)})${missingText}`;
}

function humanize(seconds: number): string {
    if (seconds >= 86400 * 365) {
        return `${seconds} seconds (~${(seconds / (86400 * 365)).toFixed(1)} years)`;
    }
    if (seconds >= 86400) {
        return `${seconds} seconds (~${(seconds / 86400).toFixed(1)} days)`;
    }
    if (seconds >= 3600) {
        return `${seconds} seconds (~${(seconds / 3600).toFixed(1)} hours)`;
    }
    return `${seconds} seconds`;
}

function missingFlags(parsed: ParseDirective): string[] {
    const missing: string[] = [];
    if (parsed['includesubdomains'] !== true) missing.push('includeSubDomains');
    if (parsed['preload'] !== true) missing.push('preload');
    return missing;
}

function finding(
    id: string,
    status: Finding['status'],
    points: number,
    reason: string,
): Finding {
    return { id, category: 'header', kind: 'grade', status, points, reason };
}

function anomalyFinding(
    id:string,
    status:Finding['status'],
    points:number,
    reason:string
):Finding {
    return {id, category:'header' ,kind:'anomaly' , status , points, reason}
}

function absurdMaxAgePoints(maxAge: number):number{
    const excess = maxAge - TEN_YEARS;
    if(excess<=0)return 0;
    const span = RFC_MAX_AGE - TEN_YEARS;
    const raw = 5 + (excess/span)*5;
    return Math.min(10 , raw);
}

export function analyzeStrictTransportAnomaly(
    rawHeader:string | null | undefined,
    parsed: ParseDirective
):Finding{
    if(rawHeader == null || rawHeader.trim()===''){
        return anomalyFinding("hsts-0" , "informational" , 0 , "No Strict-Transport-Security header present");
    }
    const hasmaxAge = "max-age" in parsed;
    const maxAge = parsed['max-age'];
    if(!hasmaxAge){
        return anomalyFinding(
            "hsts-1",
            "malformed",
            2,
            `Header is present (${JSON.stringify(rawHeader)}) but missing the required max-age directive; browsers ignore the whole header`
        );
    }
    if(maxAge===0){
        return anomalyFinding(
            "hsts-2",
            "informational",
            0,
            "max-age = 0 explicitly disables HSTS (configuration choice, not an anomaly)"
        );
    }
   
    if(typeof maxAge !== "number"){
        return anomalyFinding(
            "hsts-3",
            "malformed",
            10,
            `max-age is not numeric: ${JSON.stringify(maxAge)}`
        );
    }
    if(maxAge<0){
        return anomalyFinding(
            "hsts-4",
            "malformed",
            2,
            `max-age is negative (${maxAge}); browsers clamp to 0, so this is equivalent to max-age=0`
        );
    }
    if(maxAge>TEN_YEARS){
        const pts =Math.round(absurdMaxAgePoints(maxAge));
        return anomalyFinding(
            "hsts-5",
            "suspicious",
            pts,
            `max-age is ${maxAge} seconds (>${TEN_YEARS} = 10), which exceeds any meaningful policy and may indicate overflow or misconfiguration`
        )
    }
    return anomalyFinding(
        "hsts-6",
        "informational",
        0,
        `HSTS configuration looks normal (max-age = ${maxAge}) seconds`
    );
}