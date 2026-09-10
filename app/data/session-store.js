'use strict';
const session=require('express-session');
class BoundedSessionStore extends session.Store {
  constructor(){super();this.sessions=new Map();this.timer=setInterval(()=>this.prune(),30000);this.timer.unref();}
  prune(){for(const [id,entry] of this.sessions)if(entry.expires<=Date.now())this.sessions.delete(id);}
  get(id,callback){this.prune();const entry=this.sessions.get(id);callback(null,entry?JSON.parse(entry.value):null);}
  set(id,value,callback=()=>{}){
    this.prune();
    const authenticated=Number.isSafeInteger(value.userId) && value.userId>0;
    const peers=[...this.sessions].filter(([other,entry])=>other!==id && entry.authenticated===authenticated);
    if(authenticated && peers.length>=800)return callback(new Error('Authenticated session capacity reached'));
    // Short-lived anonymous form sessions cannot consume authenticated capacity.
    // Evict the oldest anonymous entry instead of locking out new visitors.
    if(!authenticated && peers.length>=200)this.sessions.delete(peers[0][0]);
    const ttl=authenticated?3600000:120000;
    this.sessions.set(id,{authenticated,value:JSON.stringify(value),expires:Math.min(Date.now()+ttl,new Date(value.cookie.expires).getTime()||Date.now()+ttl)});
    callback();
  }
  destroy(id,callback=()=>{}){this.sessions.delete(id);callback();}
}
module.exports={BoundedSessionStore};
