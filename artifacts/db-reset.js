'use strict';
// Idempotent schema initialization. No fixed accounts or passwords, no data deletion.
const {connect}=require('../app/data/database');
const config=require('../config/config');
connect(config.db,(error,database,client)=>{
  if(error){console.error('Database initialization failed');process.exitCode=1;return;}
  console.log('Database initialized. Create demo accounts through the signup form.');
  client.close().catch(()=>{process.exitCode=1;});
});
