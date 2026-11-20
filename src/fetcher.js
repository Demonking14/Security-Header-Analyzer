"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.fetcher = fetcher;
async function fetcher(url) {
    try {
        const parsedUrl = new URL(url);
        if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
            return {
                message: 'Not a valid protocol'
            };
        }
        const response = await fetch(parsedUrl.toString());
        return {
            message: 'Successful',
            statuscode: response.status
        };
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        console.log(error);
        return {
            message: 'Error in fetcher function',
            error: errorMessage
        };
    }
}
const res1 = await fetcher('https://example.com');
console.log(res1);
const res2 = await fetcher('https://github.com');
console.log(res2);
const res3 = await fetcher('ftp://x');
console.log(res3);
const res4 = await fetcher('not a url, http://192.168.1.10');
console.log(res4);
