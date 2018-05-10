var mongoose = require('mongoose');

mongoose.connect('mongodb://localhost/infect', {
  keepAlive: true,
  reconnectTries: Number.MAX_VALUE
});
