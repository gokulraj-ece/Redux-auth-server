const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Defining the model
const userSchema = new Schema({
  email: { type: String, unique: true, lowercase: true },
  password: String
});

// On save hook, encrypt password
// run this function before the user gets saved
userSchema.pre('save', function(next) {
  // get access to user model
  const user = this;

  // generate a salt then run callback
  bcrypt.genSalt(10, function(err, salt) {
    if (err) { return next(err); }

    // hash our user using the salt then run callback
    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) { return next(err); }

      // overwrite plain text with encrypted one
      user.password = hash;
      // go ahead with the next steps
      next();
    })
  });
});

// instances will have access to these methods
userSchema.methods.comparePassword = function(candidatePassword, callback) {
  // this.password is the hashed password
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) { return callback(err); }
    callback(null, isMatch);
  })
}

// Create the model class
const ModelClass = mongoose.model('user', userSchema);

// export the model
module.exports = ModelClass;
