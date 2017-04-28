const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
   // sub: subject, iat: issued at time
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  // user's email and pwd authorized already, give them a token
  // get the user from the done callback in passport
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res.status(422).send({ error: 'Provide username and password'});
  }
  // check whether user with given mail exists
  User.findOne({ email: email }, function(err, existingUser) {
    if (err) { return next(err); }
    // if true, return error
      if (existingUser) {
        return res.status(422).send({ error: 'Email exists'});
      }
    // else, create and save record
      const user = new User({
        email: email,
        password: password
      });
      // save the user representation saved in memory
      user.save(function(err) {
        if (err) { return next(err); }
            // respond to req stating user was created
        res.json({ token: tokenForUser(user) });
      });

  });
};
