const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createApp}=require('../server');
const {callbacks}=require('../app/data/database');
const passwords=require('../app/data/passwords');

test('current MongoDB driver adapter preserves query, replacement and insert results',async()=>{
  const seen=[];
  const col={
    async replaceOne(...args){seen.push(args);return {modifiedCount:1};},
    async insertOne(doc){return {insertedId:doc._id};},
    async findOneAndUpdate(q,u,o){assert.equal(o.returnDocument,'after');return {seq:4};}
  };
  const collection=callbacks({collection(){return col;}}).collection('users');
  const call=(method,...args)=>new Promise((resolve,reject)=>collection[method](...args,(e,r)=>e?reject(e):resolve(r)));
  assert.deepEqual(await call('insert',{_id:1}),{ops:[{_id:1}]});
  await call('update',{_id:1},{name:'test'},{upsert:true});
  assert.deepEqual(seen[0],[{_id:1},{name:'test'},{upsert:true}]);
  assert.deepEqual(await call('findAndModify',{_id:'userId'},[],{$inc:{seq:1}},{new:true}),{value:{seq:4}});
});

test('login, CSRF, escaped allocation view and disabled unrelated lessons',async t=>{
  const user={_id:1,userName:'demo',password:await passwords.hash('fixture-password'),firstName:'<script>alert(1)</script>',lastName:'Test'};
  const db={collection(name){return {
    findOne(query,cb){cb(null,user);},
    update(query,document,options,cb){cb(null,{modifiedCount:1});},
    find(query){return {toArray(cb){cb(null,[{userId:1,stocks:20,funds:30,bonds:50}]);}};}
  };}};
  const server=createApp(db).listen(0,'127.0.0.1');
  await new Promise(r=>server.once('listening',r));
  t.after(()=>new Promise(r=>server.close(r)));
  const url='http://127.0.0.1:'+server.address().port;
  const landing=await fetch(url+'/',{redirect:'manual'});assert.equal(landing.status,302);assert.equal(landing.headers.get('location'),'/login');assert.equal(landing.headers.get('set-cookie'),null);
  const login=await fetch(url+'/login');assert.equal(login.status,200);
  const cookie=login.headers.get('set-cookie').split(';')[0];
  const html=await login.text();
  const token=html.match(/name="_csrf" value="([a-f0-9]{64})"/)[1];
  const bad=await fetch(url+'/login',{method:'POST',headers:{Cookie:cookie,'Content-Type':'application/x-www-form-urlencoded'},body:'userName=demo&password=fixture-password'});
  assert.equal(bad.status,403);
  const ok=await fetch(url+'/login',{method:'POST',redirect:'manual',headers:{Cookie:cookie,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({userName:'demo',password:'fixture-password',_csrf:token})});
  assert.equal(ok.status,302);
  const authCookie=ok.headers.get('set-cookie').split(';')[0];
  const view=await fetch(url+'/allocations/1',{headers:{Cookie:authCookie}});
  assert.equal(view.status,200);
  const page=await view.text();assert.ok(page.includes('&lt;script&gt;'));assert.ok(!page.includes('<script>alert(1)</script>'));
  const form=await fetch(url+'/contributions',{headers:{Cookie:authCookie}});
  assert.equal(form.status,200);
  const formHtml=(await form.text()).replace(/<!--[\s\S]*?-->/g,'');
  const csrf=formHtml.match(/name="_csrf" value="([a-f0-9]{64})"/)[1];
  const saved=await fetch(url+'/contributions',{method:'POST',headers:{Cookie:authCookie,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({_csrf:csrf,preTax:'10',afterTax:'5',roth:'0'})});
  assert.equal(saved.status,200);
  assert.ok((await saved.text()).includes('success'));
  const invalid=await fetch(url+'/allocations/1?threshold=1%27%3Breturn%20true',{headers:{Cookie:authCookie}});
  assert.equal(invalid.status,400);
  assert.equal((await fetch(url+'/research',{headers:{Cookie:authCookie}})).status,404);
});

test('passwords are salted and asynchronous; incorrect passwords are rejected',async()=>{
  const [a,b]=await Promise.all([passwords.hash('long demo password'),passwords.hash('long demo password')]);
  assert.notEqual(a,b);
  assert.equal(await passwords.verify('long demo password',a),true);
  assert.equal(await passwords.verify('wrong password',a),false);
  assert.equal(await passwords.verify('long demo password','public-old-password'),false);
});

test('anonymous traffic cannot consume authenticated session capacity',()=>{
  const {BoundedSessionStore}=require('../app/data/session-store');
  const store=new BoundedSessionStore();
  const session={cookie:{expires:new Date(Date.now()+3600000)}};
  store.set('authenticated',{...session,userId:1},e=>assert.ifError(e));
  for(let i=0;i<1000;i++)store.set(String(i),session,e=>assert.ifError(e));
  assert.equal(store.sessions.size,201);
  store.get('authenticated',(e,value)=>{assert.ifError(e);assert.equal(value.userId,1);});
  store.get('0',(e,value)=>{assert.ifError(e);assert.equal(value,null);});
  const id=[...store.sessions.keys()].find(id=>id!=='authenticated');
  assert.ok(store.sessions.get(id).expires<=Date.now()+120000);
  store.sessions.get(id).expires=Date.now()-1;
  store.get(id,(e,value)=>{assert.ifError(e);assert.equal(value,null);});
  clearInterval(store.timer);
});
