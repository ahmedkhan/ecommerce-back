const User = require("../models/user");
const jwt = require("jsonwebtoken") // to gen signed token 
const expressJwt = require('express-jwt') // for Auth


const { errorHandler } = require("../helpers/dbErrorHandler");

exports.signup = (req, res) => {
     console.log("req.body", req.body);
    const user = new User(req.body);
    user.save((err, user) => {
        if (err) {
            return res.status(400).json({
                error: errorHandler(err)
            });
        }
        user.salt = undefined;
        user.hashed_password = undefined;
        res.json({
            user
        });
    });
};

exports.signin = (req,res)=>{
    // find user based on email 
    const {email,password} = req.body;
    User.findOne({email},(err,user)=>{
        if (err || !user){
            return res.status(400).json({
                error : "User with that Email is not Exist please signup"
            })
        }

        // if User is found make Sure the email and password match 
        // create authenticate method in user Model 
        if (!user.authenticate(password)){
            return res.status(401).json({
                error : "Email and Password Dont Match"
            });
        }


        // genrate a signin token 

        const token = jwt.sign({_id : user._id}, process.env.JWT_SECRET)
        //persist the token with t in cookies with expiry date 
        res.cookie('t',token, {expire:new Date()+9999})

        // return res with user and token to front end client 
        const {_id,name,email,role} = user 
        return res.json({token,user:{_id,name,email,role}}) 
    })

}

exports.signout = (req,res)=>{
    res.clearCookie('t');
    res.json({message: "SignOut Successfully"});

}

exports.requireSignin = expressJwt({
    secret: process.env.JWT_SECRET,
    userProperty: "auth"
});

exports.isAuth = (req, res, next) => {
    let user = req.profile && req.auth && req.profile._id == req.auth._id;
    if (!user) {
        return res.status(403).json({
            error: "Access denied"
        });
    }
    next();
};

exports.isAdmin = (req, res, next) => {
    if (req.profile.role === 0) {
        return res.status(403).json({
            error: "Admin resourse! Access denied"
        });
    }
    next();
};
