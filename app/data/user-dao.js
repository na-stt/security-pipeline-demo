'use strict';
const passwords=require('./passwords');
function UserDAO(db){
  const users=db.collection('users');
  this.addUser=(userName,firstName,lastName,password,email,callback)=>{
    passwords.hash(password).then(hash=>{
      this.getNextSequence('userId',(error,id)=>{
        if(error)return callback(error);
        const date=new Date();date.setUTCDate(date.getUTCDate()+365);
        const user={_id:id,userName,firstName,lastName,email,password:hash,benefitStartDate:date.toISOString().slice(0,10)};
        users.insert(user,(error,result)=>callback(error,error?null:result.ops[0]));
      });
    },callback);
  };
  this.validateLogin=(userName,password,callback)=>{
    if(typeof userName!=='string'||typeof password!=='string'||password.length>128)return callback(new Error('Invalid credentials'));
    users.findOne({userName},(error,user)=>{
      if(error)return callback(error);
      passwords.verify(password,user?.password).then(valid=>{
        if(valid)return callback(null,user);
        callback(Object.assign(new Error('Invalid credentials'),{invalidPassword:true}));
      },callback);
    });
  };
  this.getUserById=(id,callback)=>users.findOne({_id:parseInt(id,10)},callback);
  this.getUserByUserName=(userName,callback)=>users.findOne({userName},callback);
  this.getNextSequence=(name,callback)=>db.collection('counters').findAndModify({_id:name},[],{$inc:{seq:1}},{new:true},
    (error,data)=>error?callback(error):data?.value?callback(null,data.value.seq):callback(new Error('Database must be initialized')));
}
module.exports={UserDAO};
