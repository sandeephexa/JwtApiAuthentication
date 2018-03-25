var express = require("express");
var router = express.Router();
var bodyParser = require('body-parser');

router.use(bodyParser.urlencoded({extended : false}));
router.use(bodyParser.json());

var User = require('../user/User');

var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require('../config');

// router endpoint for register POST

router.post('/register', function(req,res) {

    var hashedPassword = bcrypt.hashSync(req.body.password, 8);
   
    User.create({
        name : req.body.name,
        password : req.body.password,
        email : req.body.email
    },
     function(err,user){
        if(err) return res.status(500).send('There was a problem registering user.')
        
        // create token
        var token = jwt.sign({id : user._id}, config.secret , {expiresIn : 86400});
        console.log("register token "+token);
        res.status(200).send({auth : true, token : token});
    });

});

// endpoint for get user

router.get('/me', function(req, res) {
  var token = req.headers['x-access-token'];
  if (!token) return res.status(401).send({ auth: false, message: 'No token provided.' });
  
  jwt.verify(token, config.secret, function(err, decoded) {
    if (err) {
        
        res.status(500).send({ auth: false, message: 'Failed to authenticate token.'});
        console.log("token error "+err);
    }
    
    
    // res.status(200).send(decoded);
    User.findById(decoded.id,{ password: 0 }, function(err,user){
        if(err) return res.status(500).send("There was a problem finding user");
        console.log(err);
        if(!user) return res.status(404).send("No user found");

        res.status(200).send(user);
        
    })

  });
});


// login endpoint
router.post('/login', function(req, res) {
  User.findOne({ email: req.body.email }, function (err, user) {
    if (err) return res.status(500).send('Error on the server.');
    if (!user) return res.status(404).send('No user found.');
  
    var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
      console.log("password sent "+req.body.password);
        console.log("password from DB "+user.password);
    // if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });
    if(req.body.password == user.password){
    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 86400 // expires in 24 hours
    });
    console.log("token from login"+token);
    res.status(200).send({ auth: true, token: token });
}
    else{
         res.status(401).send({ auth: false, token: null });
    }
  });
}); 
// router.post('/login', function(req,res){

//     User.findOne({email : req.body.email}, function(err,user){
//         if(err) return res.status(500).send("error on the server");
//         if(!user) return res.status(404).send("no user found");

//         var passwordIsvalid = bcrypt.compareSync(req.body.password, user.password);
//         console.log("password valid ?"+passwordIsvalid);
//         if(!passwordIsvalid) return res.status(401).send({auth : false,token:null});

//         var token = jwt.sign({id : user._id}, config.secret, {expiresIn : 86400});
//         console.log("login token "+token);
//         res.status(200).send({auth : true, token:token});
//     });
    
// });

// logout endpoint
router.get('/logout', function(req, res) {
  res.status(200).send({ auth: false, token: null });
});




module.exports = router;











