var express = require('express');
var router = express.Router();
var mongoose = require('mongoose');
var Pem = mongoose.model('Pem');
var crypto = require('crypto');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.post('/encrypt', function(req, res, next) {
  if (req.body.app_key !== process.env.APP_KEY) {
    res.status(401).send('unauthorized');
  }

  new Pem({
    pem: req.body.pem,
    pub: req.body.pub,
    decryptionToken: crypto.randomBytes(10).toString('hex')
  }).save(function(err, pem) {
    res.status(200).send(pem._id);
  });
});

router.post('/decrypt', function(req, res, next) {
  if (req.body.app_key !== process.env.APP_KEY) {
    res.status(401).send('unauthorized');
  }
  
  Pem.findOne({
    pub: req.body.pub,
    decryptionToken: req.body.decryptionToken
  }).exec(function(err, pem) {
    if (!pem) {
      res.status(404).send("Not found");
      return;
    }
    res.status(200).json({ pem: pem.pem });
  });
});

module.exports = router;
