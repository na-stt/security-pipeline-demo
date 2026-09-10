'use strict';
const {MongoClient} = require('mongodb');
// Keep the training DAOs' callback interface while using the current MongoDB driver.
function callbacks(database) {
  const done = (promise, callback) => promise.then(value => callback(null,value), error => callback(error));
  return {
    dropCollection(name, callback) { done(database.dropCollection(name),callback); },
    collection(name) {
      const col=database.collection(name);
      return {
        find(query) {return {toArray(callback) {done(col.find(query).toArray(),callback);}};},
        findOne(query, callback) {done(col.findOne(query),callback);},
        insert(document, callback) {done(col.insertOne(document).then(()=>({ops:[document]})),callback);},
        insertMany(documents, callback) {done(col.insertMany(documents).then(()=>({ops:documents})),callback);},
        update(query, document, options, callback) {
          if (typeof options==='function') {callback=options;options={};}
          const operation=Object.keys(document).some(k=>k.startsWith('$')) ? col.updateOne(query,document,options) : col.replaceOne(query,document,options);
          done(operation,callback);
        },
        findAndModify(query, sort, update, options, callback) {
          done(col.findOneAndUpdate(query,update,{returnDocument:options.new?'after':'before'}).then(value=>({value})),callback);
        }
      };
    }
  };
}
function connect(uri, callback) {
  MongoClient.connect(uri).then(async client=>{
    try {
      const database=client.db();
      await database.collection('users').createIndex({userName:1},{unique:true});
      await database.collection('counters').updateOne({_id:'userId'},{$setOnInsert:{seq:0}},{upsert:true});
      callback(null,callbacks(database),client);
    } catch(error){await client.close();callback(error);}
  },error=>callback(error));
}
module.exports={connect,callbacks};
