const { Signer } = require('bip322-js');
const fs=require('fs');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const sig=Signer.sign(input.privateKey,input.address,input.message);
process.stdout.write(JSON.stringify({signature:sig}));
