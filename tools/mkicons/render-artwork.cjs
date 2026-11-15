// Optional artwork regeneration. Normal Go/CI builds use the checked-in PNGs.
// Uses an installed Chromium browser solely to rasterize local SVG geometry.
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const panel = path.join(root, 'internal/ui/panel');
const work = path.join(root, 'build/artwork-render');
const browsers = [process.env.ARTWORK_BROWSER,
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'];
const browser = browsers.find(p=>p && fs.existsSync(p));
if (!browser) throw new Error('Set ARTWORK_BROWSER to an installed Chromium browser.');
fs.mkdirSync(work,{recursive:true});
const main=fs.readFileSync(path.join(panel,'icon.svg'),'utf8');
const small=fs.readFileSync(path.join(panel,'icon-small.svg'),'utf8');
const items=[{name:'icon.png',size:1024,svg:main}];
for (const [logical,weight] of [[16,14/11],[20,12.8/11],[24,12/11],[32,1]]) {
  items.push({name:`icons/small-${logical}.png`,size:256,svg:small,weight});
}
const input=path.join(work,'render.html');
fs.writeFileSync(input,`<!doctype html><meta charset="utf-8"><pre id="assets"></pre><script>
const items=${JSON.stringify(items)};
Promise.all(items.map(item=>new Promise((resolve,reject)=>{
  let svg=item.svg;
  if(item.weight){
    const doc=new DOMParser().parseFromString(svg,'image/svg+xml');
    const shield=doc.querySelector('#shield');
    const stroke=Number(shield?.getAttribute('stroke-width'));
    if(!shield || !(stroke>0)){reject(new Error('Shield stroke is missing'));return;}
    shield.setAttribute('stroke-width',String(stroke*item.weight));
    svg=new XMLSerializer().serializeToString(doc);
  }
  const image=new Image();image.onload=()=>{
    const c=document.createElement('canvas');c.width=c.height=item.size;
    c.getContext('2d').drawImage(image,0,0,item.size,item.size);
    resolve({name:item.name,size:item.size,png:c.toDataURL('image/png').split(',')[1]});
  };image.onerror=()=>reject(new Error(item.name));
  image.src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(svg);
}))).then(items=>document.getElementById('assets').textContent=JSON.stringify(items));
</script>`);
const htmlURL=require('node:url').pathToFileURL(input).href;
const result=spawnSync(browser,['--headless=new','--disable-gpu','--no-first-run',
  '--no-default-browser-check','--disable-background-networking',
  '--user-data-dir='+path.join(work,'browser-profile'),
  '--dump-dom','--virtual-time-budget=4000',htmlURL],
  {encoding:'utf8',windowsHide:true,timeout:30000,maxBuffer:4*1024*1024});
fs.writeFileSync(path.join(work,'browser.log'),result.stderr||'');
if(result.error||result.status!==0) throw result.error||new Error('SVG rasterization failed; see build/artwork-render/browser.log');
const match=result.stdout.match(/<pre id="assets">([\s\S]*?)<\/pre>/);
if(!match?.[1]) throw new Error('SVG rasterization did not finish.');
const rendered=JSON.parse(match[1]);
if(rendered.length!==items.length) throw new Error('Incomplete artwork set.');
for(const item of rendered){
  const dest=path.join(panel,item.name);
  fs.mkdirSync(path.dirname(dest),{recursive:true});
  fs.writeFileSync(dest,Buffer.from(item.png,'base64'));
  console.log(`Rendered ${item.name}: ${item.size}×${item.size}`);
}
