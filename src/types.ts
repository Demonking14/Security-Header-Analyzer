export type FetchResult = |{
    ok:true,
    requestedUrl : string;
    finalUrl : string;
    statusCode:number;
    headers:Record<string,string>;
    setCookies:string[];
    redirectChain:RedirectHop[];
} | {
    ok:false;
    requestedUrl:string;
    errorCategory:FetchErrorCategory;
    errorMessage:string;
}

export type RedirectHop = {
    url:string;
    statusCode: number;
    location:string;
}

export type FetchErrorCategory = |'invalid_url' | 'timeout'| 'network_error' | 'unknown' | 'too_many_redirects';

export type FindingStatus = 'missing' | 'weak' | 'strong' | 'malformed' | 'informational';

export type Finding = {
    id: string;
    category : 'header' | 'url' | 'redirect' | 'certificate' | 'domain';
    kind:'grade' | 'anomaly';
    status: FindingStatus;
    points :number;
    reason : string;
}