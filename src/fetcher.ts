import { FetchResult, RedirectHop , FetchErrorCategory} from "./types";
async function fetchWithRedirects(startUrl: string , originalUrl:string):Promise<FetchResult> {
        const chain: RedirectHop[] = [];
            while (true) {
                const response = await fetch(startUrl, {
                    signal: AbortSignal.timeout(2000),
                    redirect: 'manual'
                });
                const isRedirect = response.status === 301 || response.status === 302 || response.status === 303 || response.status === 307 || response.status === 308;
                if (!isRedirect) {
                    return {
                        ok: true,
                        requestedUrl: originalUrl,
                        finalUrl: startUrl,
                        statusCode: response.status,
                        headers: {
                            'strict-transport-security': response.headers.get('strict-transport-security') ?? "",
                            'content-security-policy': response.headers.get('content-security-policy') ?? "",
                            'x-frame-options': response.headers.get('x-frame-options') ?? "",
                            'x-content-type-options': response.headers.get('x-content-type-options') ?? "",
                            'referrer-policy': response.headers.get('referrer-policy') ?? ""
                        },
                        setCookies:response.headers.getSetCookie(),
                        redirectChain:chain
                    };
                }
                const location = response.headers.get('location');
                if(!location){
                    throw new Error('Redirect missing location header');
                }
                const nextUrl = new URL(location, startUrl).toString();
                if(chain.some(hop => hop.url === nextUrl)){
                    throw new Error('Redirect loop detected');
                }
                if(chain.length>=5){
                    throw new Error('Too many redirects');
                }
                chain.push({url:startUrl , statusCode:response.status , location:nextUrl});
                startUrl = nextUrl;
            }
}
export async function fetcher(url: string): Promise<FetchResult> {
    let parsedUrl: URL | undefined;
    try {
        parsedUrl = new URL(url);
        if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
            return {
                ok: false,
                errorCategory: 'invalid_url',
                errorMessage: 'Protocol must be http or https',
                requestedUrl: url
            };
        }
    } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'URL cant be parsed'
        return {
            ok: false,
            errorCategory: 'invalid_url',
            errorMessage: errorMsg,
            requestedUrl: url

        }
    }
    if (!parsedUrl) {
        return {
            ok: false,
            requestedUrl: url,
            errorCategory: 'invalid_url',
            errorMessage: 'Unable to parse url'
        }
    }
    try {
        let currentUrl = parsedUrl.toString();
        return await fetchWithRedirects(currentUrl, url);
        
    } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        let category: FetchErrorCategory = 'network_error';
        if(errorMessage.includes('loop') || errorMessage.includes('redirects')){
            category='too_many_redirects';
        }else if(error instanceof Error && error.name === 'TimeoutError'){
            category='timeout';
        }
        return {
            ok: false,
            errorCategory:category,
            requestedUrl: url,
            errorMessage: errorMessage
        };
    }
}