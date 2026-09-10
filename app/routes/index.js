'use strict';
const SessionHandler=require('./session');
const ContributionsHandler=require('./contributions');
const AllocationsHandler=require('./allocations');
// Focus this fork on the two reviewed demo scenarios. Other NodeGoat lessons are
// reference material only and are not mounted in the running application.
module.exports=(app,db)=>{
  const sessions=new SessionHandler(db), contributions=new ContributionsHandler(db), allocations=new AllocationsHandler(db);
  const authenticated=sessions.isLoggedInMiddleware;
  app.get('/',(req,res)=>res.redirect('/login'));
  app.get('/login',sessions.displayLoginPage);
  app.post('/login',sessions.handleLoginRequest);
  app.get('/signup',sessions.displaySignupPage);
  app.post('/signup',sessions.handleSignup);
  app.get('/logout',sessions.displayLogoutPage);
  app.get('/dashboard',authenticated,sessions.displayWelcomePage);
  app.get('/contributions',authenticated,contributions.displayContributions);
  app.post('/contributions',authenticated,contributions.handleContributionsUpdate);
  app.get('/allocations/:userId',authenticated,allocations.displayAllocations);
};
