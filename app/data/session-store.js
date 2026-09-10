'use strict';
const session=require('express-session');
class BoundedSessionStore extends session.Store {
  constructor(){super();this.sessions=new Map();this.timer=setInterval(()=>this.prune(),60000);this.timer.unref();}
  prune(){for(const [id,entry] of this.sessions)if(entry.expires<=Date.now())this.sessions.delete(id);}
  get(id,callback){this.prune();const entry=this.sessions.get(id);callback(null,entry?JSON.parse(entry.value):null);}
  set(id,value,callback=()=>{}){
    this.prune();
    if(!this.sessions.has(id)&&this.sessions.size>=1000)return callback(new Error('Session capacity reached'));
    this.sessions.set(id,{value:JSON.stringify(value),expires:Math.min(Date.now()+3600000,new Date(value.cookie.expires).getTime()||Date.now()+3600000)});
    callback();
  }
  destroy(id,callback=()=>{}){this.sessions.delete(id);callback();}
}
module.exports={BoundedSessionStore};
