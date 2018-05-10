var express = require('express');
var router = express.Router();
var mongoose = require('mongoose');
var Pem = mongoose.model('Pem');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.post('/encrypt', function(req, res, next) {
  console.log(req.body)
  
  new Pem({
    pem: req.body.pem,
    pub: req.body.pub
  }).save(function(err, pem) {
    res.status(200).send(pem._id);
  });
});

router.post('/decrypt', function(req, res, next) {
  if (req.body.app_key !== '123123kj123123123kjjlkjlkj123') {
    res.status(401).send('unauthorized');
  }
  
  console.log(req.body)

  Pem.findOne({
    pub: req.body.pub
  }).exec(function(err, pem) {
    res.status(200).json({ pem: pem.pem });
  });
});

module.exports = router;
