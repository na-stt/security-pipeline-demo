'use strict';
const {randomBytes,scrypt,timingSafeEqual}=require('node:crypto');
let active=0;
function derive(password,salt){
  if(active>=4)return Promise.reject(new Error('Password processing busy'));
  active++;
  return new Promise((resolve,reject)=>scrypt(password,salt,64,(error,key)=>{
    active--;if(error)reject(error);else resolve(key);
  }));
}
async function hash(password){
  const salt=randomBytes(16).toString('hex');
  return `scrypt:${salt}:${(await derive(password,salt)).toString('hex')}`;
}
async function verify(password,stored){
  const match=/^scrypt:([a-f0-9]{32}):([a-f0-9]{128})$/.exec(stored||'');
  const key=await derive(password,match?match[1]:'0'.repeat(32));
  return !!match && timingSafeEqual(key,Buffer.from(match[2],'hex'));
}
module.exports={hash,verify};
