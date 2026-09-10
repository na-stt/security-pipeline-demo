'use strict';
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const nunjucks = require('nunjucks');
const {randomBytes, timingSafeEqual} = require('node:crypto');
const path = require('node:path');
const {connect} = require('./app/data/database');
const config = require('./config/config');

function createApp(database) {
  const app=express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.get('/healthz', (req,res)=>res.json({ok:true}));
  app.use(express.static(path.join(__dirname,'app/assets')));
  app.use(express.urlencoded({extended:false,limit:'16kb'}));
  app.use(express.json({limit:'16kb'}));
  app.use(session({secret:process.env.SESSION_SECRET || randomBytes(32).toString('hex'),
    resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'strict',maxAge:3600000}}));
  app.use((req,res,next)=>{
    req.session.csrf ||= randomBytes(32).toString('hex');
    res.locals.csrftoken=req.session.csrf;
    if (!['GET','HEAD','OPTIONS'].includes(req.method)) {
      const supplied=req.body?._csrf;
      if (typeof supplied!=='string' || Buffer.byteLength(supplied)!==64 || !timingSafeEqual(Buffer.from(supplied),Buffer.from(req.session.csrf)))
        return res.status(403).send('Invalid CSRF token');
    }
    next();
  });
  nunjucks.configure(path.join(__dirname,'app/views'),{autoescape:true,express:app,noCache:true});
  app.set('view engine','html');
  require('./app/routes')(app,database);
  app.use((error,req,res,next)=>res.status(500).send('Request failed'));
  return app;
}
if (require.main===module) connect(config.db,(error,database)=>{
  if(error){console.error('Database connection failed');process.exitCode=1;return;}
  createApp(database).listen(config.port,'0.0.0.0');
});
module.exports={createApp};
