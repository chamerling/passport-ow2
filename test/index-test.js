var vows = require('vows');
var assert = require('assert');
var util = require('util');
var github = require('passport-ow2');


vows.describe('passport-ow2').addBatch({
  
  'module': {
    'should report a version': function (x) {
      assert.isString(ow2.version);
    },
  },
  
}).export(module);
