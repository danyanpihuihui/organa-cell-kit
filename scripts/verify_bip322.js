#!/usr/bin/env node
const { Verifier } = require('bip322-js');
let input='';
process.stdin.setEncoding('utf8');
process.stdin.on('data', c => input += c);
process.stdin.on('end', () => {
  try {
    const claim=JSON.parse(input);
    if (!claim.signing_address || !claim.message || !claim.signature) throw new Error('address, message and signature are required');
    const ok=Verifier.verifySignature(claim.signing_address, claim.message, claim.signature);
    process.stdout.write(JSON.stringify({ok:!!ok}));
    if (!ok) process.exitCode=1;
  } catch (e) {
    process.stdout.write(JSON.stringify({ok:false,error:String(e && e.message ? e.message : e)}));
    process.exitCode=1;
  }
});
