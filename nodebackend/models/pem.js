var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var Pem = new Schema({
  pem: {
    type: String
  },
  pub: {
    type: String
  },
  decryptionToken: {
    type: String
  }
});

mongoose.model('Pem', Pem);
