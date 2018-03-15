const express = require('express');
const bodyParser = require('body-parser');
const {User} = require('./model/User');
const bcrypt = require('bcrypt');
//step1 import passport
const passport = require('passport');
const localStrategy = require('passport-local').Strategy;

app = express();
//step2 initialize it
app.use(passport.initialize());
app.use(bodyParser.json());
app.use((req, res, next) =>{
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST');
    next();
});


//step3 serialize and deserialize

passport.serializeUser((user,done)=>{
    console.log('call serializeUser');
    done(null,user);
});

passport.deserializeUser((user,done)=>{
    console.log("call deserializeUser");
    done(null,false);
});

//step4 use of passport

passport.use('login', new localStrategy({
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback: true},
    (req,email,password,done)=>{
        User.findOne({email:email},(err,user)=>{
            if(err)
            {
                console.log(err);
                return
            }
            if(!user)
            {
                console.log("User is not exists");
                return done(null,false);
            }
            if(user)
            {
                if(!validPassword(user,password))
                {
                    console.log("password is invalid");
                    return done(null,false);
                }
                return done(null, user);
            }
        })

    }))

//step5 call

app.post('/login',passport.authenticate('login',{
    successRedirect: '/home',
    failureRedirect: '/fail'
}));

app.get('/home',(req,res)=>{
    res.send(" success");
});

app.get('/fail',(req,res)=>{
    res.send(" Failed");
});


passport.use('signup',new localStrategy({
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback: true
    }, (req,email,password,done) =>{
        User.findOne({email: email}, (err, user) => {
            if (err) {
                console.log(err);
                return done(err);
            }
            if (user) {
                console.log("User is already exists");
                return done(null, false);
            }
            else {
                var userdata = new User({
                    name: req.body.name,
                    mobile: req.body.mob,
                    password: createHash(password),
                    email: email,
                    pic: req.body.pic,
                    gender: req.body.gen
                });
                userdata.save(function (err) {
                    if (err) {
                        console.log('Error in Saving user: ' + err);
                        throw err;
                    }
                    var token = userdata.genToken();
                    if (token) {
                        console.log("Registration Successful")
                        return done(null, userdata);
                    }
                    else {
                        console.log("token err");
                    }
                });
            }
        })
    })
);


app.post('/signup',passport.authenticate('signup',{
    successRedirect: '/home',
    failureRedirect: '/fail'
}));

app.get('/find',isLoggedIn,(req,res)=>{
    User.find().then(
        (data)=>{
            res.send(data);
        }
    )
});


validPassword =  (user,password)=> {
    return bcrypt.compareSync(password,user.password);
}



createHash = (password)=>{
    return bcrypt.hashSync(password,bcrypt.genSaltSync(10),null);
}

function isLoggedIn(req,res,next){
    if(req.isAuthenticated())
    {
        return next();
    }
    req.redirect('auth');
}

app.post('/auth',(req,res)=>{
    res.send("You are not authorize user");
})


app.listen(3001);



//https://medium.com/@nohkachi/local-authentication-with-express-4-x-and-passport-js-745eba47076d
// {
//     "email": "priti@gmail.com",
//     "password": "12345678",
//     "mobile": "1234567893",
//     "gender":"Female",
//     "name":"Pooja Maurya",
//     "pic": "dsdfdfdff"
// }