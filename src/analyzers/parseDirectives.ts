export interface ParseDirective{
    [key:string]:number | null| boolean | string;
}
export function parseDirective(input:string):ParseDirective{
    const results : ParseDirective = {};
    input
    .split(';')
    .map((part)=>part.trim())
    .filter((part)=>part.length>0)
    .forEach((directive)=>{
        const equalIndex = directive.indexOf('=');
        if(equalIndex == -1){
            const name = directive.toLowerCase();
            results[name]=true;
            return;
        }
        const rawName = directive.slice(0 , equalIndex).trim();
        let rawValue = directive.slice(equalIndex+1).trim();
        if(
            (rawValue.startsWith('"') && rawValue.endsWith('"')) ||
            (rawValue.startsWith("'") && rawValue.endsWith("'"))
        ){
            rawValue = rawValue.slice(1,-1);
        }
        const name = rawName.toLowerCase();
        if(!(name in results)){
            if(name == 'max-age'){
            const num = Number(rawValue);
            results[name] = Number.isNaN(num)?  null : num;
        }else{
            results[name]= rawValue;
        }
        }
    });
    return results;
}