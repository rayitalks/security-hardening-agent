const assert=require('node:assert/strict'),c=require('node:crypto');
const p=require(process.argv[2]);let checks=0;function test(name,f){f();console.log('PASS '+name);checks++;}
const phrase=c.randomBytes(32).toString('base64');
test('government profile fails closed',()=>assert.throws(()=>p.generate({algorithm:'ml-kem-768',profile:'government',passphrase:phrase}),/blocked/));
test('weak or oversized protection password rejected',()=>{for(const passphrase of ['short','x'.repeat(1025)])assert.throws(()=>p.generate({algorithm:'ml-kem-768',profile:'evaluation',passphrase}));});
test('algorithm allowlist rejects injection and unsupported algorithms',()=>{for(const algorithm of ['rsa','ml-kem-512','ml-kem-768;whoami',''])assert.throws(()=>p.generate({algorithm,profile:'evaluation',passphrase:phrase}));});
for(const algorithm of ['ml-kem-768','ml-kem-1024','ml-dsa-65','ml-dsa-87'])test(algorithm+' encrypted recovery and real key operation',()=>{const b=p.generate({algorithm,profile:'evaluation',passphrase:phrase});assert.equal(b.selfTest,'passed');assert.equal(b.moduleValidation,'not-established');assert.ok(!JSON.stringify(b).includes('BEGIN PRIVATE KEY'));assert.ok(!JSON.stringify(b).includes(phrase));const result=p.unwrap({bundle:b,passphrase:phrase,verifyOnly:true});assert.equal(result.verified,true);const recovered=p.unwrap({bundle:b,passphrase:phrase});assert.equal(c.createPrivateKey(recovered.privateKeyPem).asymmetricKeyType,algorithm);});
const bundle=p.generate({algorithm:'ml-kem-768',profile:'evaluation',passphrase:phrase});
test('incorrect password is rejected',()=>assert.throws(()=>p.unwrap({bundle,passphrase:c.randomBytes(32).toString('base64')})));
test('ciphertext tamper is rejected',()=>{const b=structuredClone(bundle);const bytes=Buffer.from(b.privateKey.ciphertext,'base64');bytes[0]^=1;b.privateKey.ciphertext=bytes.toString('base64');assert.throws(()=>p.unwrap({bundle:b,passphrase:phrase}));});
test('authenticated metadata tamper is rejected',()=>{const b=structuredClone(bundle);b.algorithm='ml-kem-1024';assert.throws(()=>p.unwrap({bundle:b,passphrase:phrase}));});
test('unbounded KDF input is rejected',()=>{const b=structuredClone(bundle);b.privateKey.iterations=999999999;assert.throws(()=>p.unwrap({bundle:b,passphrase:phrase}));});
test('modified fingerprint and validation claim are rejected',()=>{for(const field of ['publicKeySha256','moduleValidation']){const b=structuredClone(bundle);b[field]='modified';assert.throws(()=>p.unwrap({bundle:b,passphrase:phrase}));}});
test('fresh keys and protection nonces per generation',()=>{const b=p.generate({algorithm:'ml-kem-768',profile:'evaluation',passphrase:phrase});assert.notEqual(b.publicKeySha256,bundle.publicKeySha256);assert.notEqual(b.privateKey.salt,bundle.privateKey.salt);assert.notEqual(b.privateKey.iv,bundle.privateKey.iv);});
test('runtime does not certify compliance',()=>{const s=p.status();assert.equal(s.governmentReady,false);assert.equal(s.moduleValidation,'not-established');});
console.log(`${checks} PQ cryptography checks passed; no keys or passphrases printed.`);
