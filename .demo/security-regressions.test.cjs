const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Exercise actual route code with stubbed data access, without installing the app
// or starting MongoDB. This VM is a test harness, not a security sandbox.
function handler(file, daoName, dao) {
  const context = {
    module: {exports: {}},
    require(name) {
      if (name === '../../config/config') return {environmentalScripts: ''};
      if (name.startsWith('../data/')) return {[daoName]: function () {return dao;}};
      throw new Error(`Unexpected import: ${name}`);
    }
  };
  const filename = path.join(__dirname, '../app/routes', file);
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), context, {filename});
  return new context.module.exports({});
}
function response() {
  return {
    statusCode: 200,
    status(code) {this.statusCode = code; return this;},
    send(body) {this.body = body; return this;},
    render(view, data) {this.view = view; this.data = data;}
  };
}
function contribution(body) {
  const updates = [];
  const routes = handler('contributions.js', 'ContributionsDAO', {
    update(...args) {updates.push(args.slice(0, 4)); args[4](null, {});}
  });
  const res = response();
  routes.handleContributionsUpdate({body, session: {userId: 1}}, res, err => {throw err;});
  return {updates, res};
}
test('valid decimal contributions preserve values and session ownership', () => {
  const {updates} = contribution({preTax: '10.5', afterTax: '5', roth: '0'});
  assert.deepEqual(updates, [[1, 10.5, 5, 0]]);
});
test('contribution input rejects expressions instead of evaluating them', () => {
  const {updates, res} = contribution({preTax: '5+5', afterTax: '0', roth: '0'});
  assert.equal(updates.length, 0);
  assert.equal(res.data.updateError, 'Invalid contribution percentages');
});
test('invalid and over-budget contributions do not reach the database', () => {
  for (const value of ['', ' ', '-1', 'Infinity', '1e3', '31', {}, []]) {
    assert.equal(contribution({preTax: value, afterTax: '0', roth: '0'}).updates.length, 0);
  }
});
test('allocation lookup uses session identity even when URL names another user', () => {
  let selected;
  const routes = handler('allocations.js', 'AllocationsDAO', {
    getByUserIdAndThreshold(user, threshold, cb) {selected = user; cb(null, []);}
  });
  routes.displayAllocations({session: {userId: 1}, params: {userId: '2'}, query: {}}, response(), err => {throw err;});
  assert.equal(selected, 1);
});
test('allocation lookup denies missing authentication before querying', () => {
  let called = false;
  const routes = handler('allocations.js', 'AllocationsDAO', {
    getByUserIdAndThreshold() {called = true;}
  });
  const res = response();
  routes.displayAllocations({params: {userId: '2'}, query: {}}, res, err => {throw err;});
  assert.equal(res.statusCode, 401);
  assert.equal(called, false);
});
