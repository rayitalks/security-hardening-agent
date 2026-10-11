const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const path=process.argv[2];let text=fs.readFileSync(path,'utf8');text=text.slice(text.indexOf('/* RAYI_PASSWORD_FEATURE_START'),text.indexOf('/* RAYI_PASSWORD_FEATURE_END */'));
function load(c=crypto.webcrypto){const scope={module:{exports:{}},crypto:c};vm.runInNewContext(text,scope);return scope.module.exports;}
const p=load();let checks=0;function test(name,f){f();console.log('PASS '+name);checks++;}
test('all 7776 EFF words',()=>assert.equal(p.wordCount,7776));
test('password bounds and selected groups',()=>{for(const length of [8,24,64,256])for(const v of p.generate({length,count:20}).values){assert.equal(v.length,length);for(const re of [/[A-Z]/,/[a-z]/,/[0-9]/,/[^A-Za-z0-9]/])assert.match(v,re);}});
test('exclusions and compatibility',()=>{for(const v of p.generate({length:32,count:20,groups:['upper','lower','digits'],exclude:'abcABC',ambiguous:true}).values){assert.match(v,/^[A-Za-z0-9]+$/);assert.doesNotMatch(v,/[abcABCIl1O0o]/);}});
test('hex output is uniform 256-bit space',()=>{const r=p.generate({length:64,groups:['lower','digits'],exclude:'ghijklmnopqrstuvwxyz',required:false});assert.match(r.values[0],/^[0-9a-f]{64}$/);assert.equal(r.bits,256);});
test('passphrase words and entropy',()=>{const r=p.generate({mode:'phrase',words:8,count:20,separator:'.'});for(const v of r.values)assert.equal(v.split('.').length,8);assert.ok(Math.abs(r.bits-8*Math.log2(7776))<1e-10);});
test('capitalization adds zero entropy and digits add log2(10000)',()=>{const a=p.settings({mode:'phrase'}),b=p.settings({mode:'phrase',capitalize:true}),c=p.generate({mode:'phrase',suffix:true});assert.equal(a.bits,b.bits);assert.ok(Math.abs(c.bits-a.bits-Math.log2(10000))<1e-10);assert.match(c.values[0],/\.\d{4}$/);});
test('exact constrained output count',()=>{assert.equal(p.validCount(['ab','12'],2,true),8n);assert.equal(p.validCount(['abc','12','!?'],3,true),72n);});
test('empty, malformed and out-of-bounds input fails',()=>{for(const o of [{groups:[]},{groups:['no']},{groups:['digits','digits']},{length:7},{length:257},{length:NaN},{count:21},{groups:['digits'],exclude:'0123456789'},{groups:['digits'],exclude:'123456789'},{mode:'phrase',words:5},{mode:'phrase',separator:'-'},{mode:'bad'}])assert.throws(()=>p.generate(o));});
test('random modulo tail is rejected',()=>{let n=0;const mocked=load({getRandomValues(a){a[0]=n++?7:0xffffffff;return a;}});assert.equal(mocked.randomIndex(10),7);assert.equal(n,2);});
test('missing random source fails closed',()=>assert.throws(()=>load({}).generate({}),/Secure random/));
test('feature has no network, browser storage or Math.random',()=>assert.doesNotMatch(text,/\bfetch\s*\(|\bXMLHttpRequest\b|\blocalStorage\b|\bsessionStorage\b|Math\.random\s*\(/));
console.log(`${checks} password security checks passed; generated secrets not printed.`);
