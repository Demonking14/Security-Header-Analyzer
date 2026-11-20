import { parseDirective } from "../analyzers/parseDirectives";

console.log(parseDirective("max-age=31536000; includeSubdomains; preload"))
console.log(parseDirective("max-age=0"));
console.log(parseDirective(""));
console.log(parseDirective("max-age=abc"))
console.log(parseDirective("max-age=31536000; max-age=0"))
