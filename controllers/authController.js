const userModel = require('../models/user-model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { generateToken } = require("../utils/generateToken");

module.exports.registerUser = async function (req,res) {
    try {
        let {email, password, fullname} = req.body;

        let user = await userModel.findOne({email: email});
        if(user) 
        {
            req.flash("error","You already have an account, Please Login !!");
            return res.redirect("/");
        }

        bcrypt.genSalt(10, function (err, salt) {
            bcrypt.hash(password, salt, async function(err, hash){
                if(err) return res.send(err.message);
                else{
                    let user = await userModel.create({
                        email,
                        password: hash,
                        fullname,
                    });
                    let token = generateToken(user);
                    res.cookie("token", token);
                    req.flash("success","Account created successfully !!");
                    res.redirect("/shop");
                }
            });
        });
    } catch (error) {
        console.log(error.message);
    }
};

module.exports.loginUser = async function (req,res) {
    let {email, password} = req.body;

    let user = await userModel.findOne({email:email});
    if(!user)
    {
        req.flash("error","Your Account is not Registered !!");
        return res.redirect("/");
    }

    bcrypt.compare(password, user.password, function(err,result){
        if(result){
            let token = generateToken(user);
            res.cookie("token", token);
            res.redirect("/shop");
        }
        else{
            req.flash("error","Email or Password incorrect !!");
            res.redirect("/");
        }
    })
};

module.exports.logout = function(req,res) {
    res.cookie("token","");
    res.redirect("/");
};