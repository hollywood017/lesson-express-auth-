const passport = require('passport');
const bcrypt = require('bcrypt');
const LocalStrategy = require('passport-local').Strategy;


const UserModel = require('../models/user-model');

//Save the user's ID in the bowel (called when user logs in)
passport.serializeUser((userFromDb, next) => {
  next(null, userFromDb._id);
});

//Retrieve the user's info form the DB with the ID inside the bowel
passport.deserializeUser((idFromBowl, next) => {
  UserModel.findById(
    idFromBowl,
    (err, userFromDb) => {
      if(err){
        next(err);
        return;
      }
      next(null, userFromDb);
    }
  );
});


//email & password login strategy
passport.use(new LocalStrategy(
  {
    usernameField: 'loginEmail',   //sent through AJAX from angular
    passwordField: 'loginPassword' //sent through AJAX from angular
  },
  (theEmail, thePassword, next) => {
    UserModel.findOne(
      { email: theEmail },
      (err, userFromDb) => {
        if(err){
          next(err);
          return;
        }
        if(userFromDb === null) {
          next(null, false, { message: 'Incorrect email' });
        }
        if (bcrypt.compareSync(thePassword, userFromDb.encryptedPassword) === false) {
          next(null, false, { message: 'Incorrect password'});
          return;
        }
        next(null, userFromDb);
      }
    );// close UserModel.findOne()
  }// close (theEmail, thePassword, next)
));
