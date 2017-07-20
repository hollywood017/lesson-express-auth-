const express = require('express');
const bcrypt = require('bcrypt');

const UserModel = require('../models/user-model');

const router = express.Router();

//POST signup
router.post('/api/signup', (req, res, next) => {
  if(!req.body.signupEmail || !req.body.signupPassword){
    //.status helps the front end know that you have an error
    //400 for client errors (user needs to fix something)
    res.status(400).json({ message: 'Need both email and password'});
  }
  UserModel.findOne(
    {email: req.body.signupEmail },
    (err, userFromDB) => {
      if(err){
        //500 for server errors (nothing user can do)
        res.status(500).json({ message: 'Email check went to 💩'});
        return;
      }
      if(userFromDB){
        //400 for client errors (user needs to fix something)
        res.status(400).json({ message: 'Email already exists.' });
        return;
      }
      const salt = bcrypt.genSaltSync(10);
      const scrambledPassword = bcrypt.hashSync(req.body.signupPassword, salt);

      const theUser = new UserModel ({
        fullName: req.body.signupFullName,
        email: req.body.signupEmail,
        encryptedPassword: scrambledPassword
      });
      theUser.save((err) => {
        if(err) {
          res.status(500).json({ message: 'User save wen to 💩'});
          return;
        }

        req.login(theUser, (err) => {
          if(err) {
            res.status(500).json({ message: 'Login save wen to 💩'});
            return;
          }

          //clear the encryptedPassword before sending
          //(not from the database, just from the object)
          theUser.encryptedPassword = undefined;

          //send the user's information to the frontend
          res.status(200).json(theUser);

        });//close req.login()
      });//close theUser.save()
    }
  );//close UserModel.findOne()
});//close router.post



//POST login
//POST logout
//GET checklogin



module.exports = router;
