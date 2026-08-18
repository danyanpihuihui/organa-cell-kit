#!/usr/bin/env node
const { Verifier } = require('bip322-js');
let input='';
process.stdin.setEncoding('utf8');
process.stdin.on('data', c => input += c);
process.stdin.on('end', () => {
  try {
    const claim=JSON.parse(input);
    if (!claim.signing_address || !claim.message || !claim.signature) throw new Error('address, message and signature are required');
    if (typeof claim.signature !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(claim.signature) || claim.signature.length % 4 !== 0) throw new Error('canonical base64 BIP-322 signature required');
    const decoded=Buffer.from(claim.signature, 'base64');
    if (!decoded.length || decoded.toString('base64') !== claim.signature) throw new Error('canonical base64 BIP-322 signature required');
    // Compact legacy BIP-137 signatures are always 65 bytes and must never satisfy a BIP-322-Simple request.
    if (decoded.length === 65) throw new Error('legacy BIP-137 signatures are not accepted');
    if (!/^(bc1q|bc1p)/.test(claim.signing_address)) throw new Error('only native SegWit or Taproot mainnet BIP-322 addresses are accepted');
    const ok=Verifier.verifySignature(claim.signing_address, claim.message, claim.signature, true);
    process.stdout.write(JSON.stringify({ok:!!ok}));
    if (!ok) process.exitCode=1;
  } catch (e) {
    process.stdout.write(JSON.stringify({ok:false,error:String(e && e.message ? e.message : e)}));
    process.exitCode=1;
  }
});
