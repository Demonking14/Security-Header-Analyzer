import { fetcher } from '../fetcher';

async function main() {
  // const res1 = await fetcher('https://example.com');
  // console.log(res1);

  const res2 = await fetcher('http://github.com');
  console.log(res2);

  // const res3 = await fetcher('ftp://x');
  // console.log(res3);

  // const res4 = await fetcher('http://192.168.1.10');
  // console.log(res4);
  
  // const res5 = await fetcher('not a url');
  // console.log(res5);
}

main();