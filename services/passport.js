const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// create a local strategy
const localOptions = {
  usernameField: 'email'
};

const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
 // verify email and password
 User.findOne({ email: email }, function(err, user) {
   if (err) { return done(err); }
   // if user was not found
   if (!user) { return done(null, false); }
   // compare passwords - is 'password' (plain text) === 'user.password' (encrypted from db)
   // if correct email and pwd call done with true
   user.comparePassword(password, function(err, isMatch) {
    if (err) { return done(err); }
    if (!isMatch) { return done(null, false); }
    return done(null, user);
  });
 });
});

// setup options for jwt Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

//create JwtStrategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // see if user id in payload exists in our db
  User.findById(payload.sub, function(err, user) {
    if (err) { return done(err, false); } // unable to do the search
    // if true, call done with the user
    if (user) {
      done(null, user); //adds the user to req.user (to be used elsewhere)
    } else {   // else call done without user obj
      done(null, false); // did search but couldnt find user
    }
  });
});

// tell passport to use this Strategy
passport.use(jwtLogin);
passport.use(localLogin);
