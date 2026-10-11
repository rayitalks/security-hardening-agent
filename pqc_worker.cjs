'use strict';
// Fixed local crypto worker. Algorithms are implemented by Node/OpenSSL, not this app.
const c=require('node:crypto');
const ALGORITHMS=['ml-kem-768','ml-kem-1024','ml-dsa-65','ml-dsa-87'];
const SCHEMA='ray-i-pqc-key-v1',ITERATIONS=600000;
function allowed(algorithm){if(!ALGORITHMS.includes(algorithm))throw Error('Unsupported post-quantum algorithm.');}
function metadata(bundle){return Buffer.from(JSON.stringify([SCHEMA,bundle.algorithm,bundle.publicKeyPem,bundle.createdAt]),'utf8');}
function password(value){if(typeof value!=='string'||value.length<24||Buffer.byteLength(value,'utf8')>1024)throw Error('Use a unique protection passphrase of at least 24 characters, at most 1024 UTF-8 bytes.');return value;}
function checkPair(algorithm,pair){
 if(algorithm.startsWith('ml-kem-')){const{sharedKey,ciphertext}=c.encapsulate(pair.publicKey);const recovered=c.decapsulate(pair.privateKey,ciphertext);const ok=c.timingSafeEqual(sharedKey,recovered);sharedKey.fill(0);recovered.fill(0);if(!ok)throw Error('Key encapsulation self-test failed.');}
 else{const message=Buffer.from('Ray-i local key pair consistency test v1');const signature=c.sign(null,message,pair.privateKey);if(!c.verify(null,message,pair.publicKey,signature))throw Error('Signature self-test failed.');}
}
function status(){
 return{available:true,node:process.version,openssl:process.versions.openssl,fipsMode:c.getFips()===1,moduleValidation:'not-established',governmentReady:false,algorithms:ALGORITHMS,limitations:['A runtime FIPS flag is not a CMVP certificate or authorization.','Generated keys are for evaluation. Production government use requires a separately verified module, approved configuration and system authorization.']};
}
function generate(input){
 allowed(input.algorithm);password(input.passphrase);
 if(input.profile!=='evaluation')throw Error('Government key generation is blocked: this app has no verified CMVP module integration. Select local evaluation or use your approved KMS/HSM.');
 const pair=c.generateKeyPairSync(input.algorithm);checkPair(input.algorithm,pair);
 const der=pair.privateKey.export({type:'pkcs8',format:'der'}),salt=c.randomBytes(32),iv=c.randomBytes(12);
 const bundle={schema:SCHEMA,algorithm:input.algorithm,createdAt:new Date().toISOString(),publicKeyPem:pair.publicKey.export({type:'spki',format:'pem'}),purpose:input.algorithm.startsWith('ml-kem-')?'key-establishment':'digital-signatures',profile:'evaluation',moduleValidation:'not-established'};
 const key=c.pbkdf2Sync(input.passphrase,salt,ITERATIONS,32,'sha256');
 try{
  const cipher=c.createCipheriv('aes-256-gcm',key,iv,{authTagLength:16});cipher.setAAD(metadata(bundle));
  const encrypted=Buffer.concat([cipher.update(der),cipher.final()]);
  bundle.privateKey={format:'PKCS8-DER',cipher:'AES-256-GCM',kdf:'PBKDF2-HMAC-SHA256',iterations:ITERATIONS,salt:salt.toString('base64'),iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:encrypted.toString('base64')};
  bundle.publicKeySha256=c.createHash('sha256').update(pair.publicKey.export({type:'spki',format:'der'})).digest('hex');
  bundle.selfTest='passed';bundle.runtime=status();return bundle;
 }finally{key.fill(0);der.fill(0);input.passphrase='';}
}
function decode(value,min,max){if(typeof value!=='string'||value.length>max*2||!/^[A-Za-z0-9+/]*={0,2}$/.test(value))throw Error('Invalid key bundle encoding.');const b=Buffer.from(value,'base64');if(b.toString('base64')!==value||b.length<min||b.length>max)throw Error('Invalid key bundle size.');return b;}
function unwrap(input){
 password(input.passphrase);const b=input.bundle;if(!b||b.schema!==SCHEMA||typeof b.createdAt!=='string'||b.createdAt.length>50||typeof b.publicKeyPem!=='string'||b.publicKeyPem.length>12000)throw Error('Unsupported key bundle.');allowed(b.algorithm);
 if(b.profile!=='evaluation'||b.moduleValidation!=='not-established')throw Error('Unsupported key validation claim.');
 const p=b.privateKey;if(!p||p.cipher!=='AES-256-GCM'||p.kdf!=='PBKDF2-HMAC-SHA256'||p.format!=='PKCS8-DER'||p.iterations!==ITERATIONS)throw Error('Unsupported key protection parameters.');
 const salt=decode(p.salt,32,32),iv=decode(p.iv,12,12),tag=decode(p.tag,16,16),ciphertext=decode(p.ciphertext,32,32768),key=c.pbkdf2Sync(input.passphrase,salt,ITERATIONS,32,'sha256');let der;
 try{
  const decipher=c.createDecipheriv('aes-256-gcm',key,iv,{authTagLength:16});decipher.setAAD(metadata(b));decipher.setAuthTag(tag);
  der=Buffer.concat([decipher.update(ciphertext),decipher.final()]);const privateKey=c.createPrivateKey({key:der,type:'pkcs8',format:'der'}),publicKey=c.createPublicKey(privateKey);
  if(privateKey.asymmetricKeyType!==b.algorithm||publicKey.export({type:'spki',format:'pem'})!==b.publicKeyPem)throw Error('Key identity mismatch.');
  if(c.createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex')!==b.publicKeySha256)throw Error('Public key fingerprint mismatch.');
  checkPair(b.algorithm,{privateKey,publicKey});
  return input.verifyOnly?{verified:true,algorithm:b.algorithm}:{privateKeyPem:privateKey.export({type:'pkcs8',format:'pem'})};
 }finally{key.fill(0);if(der)der.fill(0);input.passphrase='';}
}
function dispatch(input){if(input.operation==='status')return status();if(input.operation==='generate')return generate(input);if(input.operation==='unwrap')return unwrap(input);throw Error('Unsupported operation.');}
module.exports={status,generate,unwrap,dispatch};
if(require.main===module){let input='',size=0;process.stdin.setEncoding('utf8');process.stdin.on('data',chunk=>{size+=Buffer.byteLength(chunk);if(size>100000){process.exitCode=1;process.stdin.destroy();return;}input+=chunk;});process.stdin.on('end',()=>{try{const result=dispatch(JSON.parse(input));input='';process.stdout.write(JSON.stringify(result));}catch{process.stderr.write('Post-quantum operation failed. Check the algorithm, runtime, profile, passphrase and bundle integrity.');process.exitCode=1;}});}
