var express = require('express');
var bodyParser = require('body-parser');
var {User} = require('./model/User');
var bcrypt = require('bcrypt');
//step1 import passport
var passport = require('passport');
var localStrategy = require('passport-local').Strategy;
var session = require('express-session');
var cors = require('cors');


app = express();
app.use(cors());


// app.use(function(req, res, next) {
//     res.header('Access-Control-Allow-Origin', "http://localhost:4200");
//     res.header('Access-Control-Allow-Credentials', true);
//     res.header('Access-Control-Expose-Headers',"content-type, cache,X-Custom-header,acesstoken");
//     res.header("AccessControlAllowMethods", "POST, GET, PUT, DELETE, OPTIONS");
//     res.header("Access-Control-Allow-Headers", "Access-Control-Allow-Headers,Origin,Access-Control-Expose-Headers, X-Requested-With, Content-Type, Accept,acesstoken");
//     next();
// });

//app.options('*', cors());
app.use(session({ secret: 'priti123', resave: true, saveUninitialized: true}));



//step2 initialize it
app.use(passport.initialize());
app.use(passport.session());

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:true}));




var token;

//step3 serialize and deserialize

passport.serializeUser((user,done)=>{
    console.log('call serializeUser');
    //console.log(user);
    done(null,user);
});

passport.deserializeUser((user,done)=>{
    console.log("call deserializeUser");
    //console.log(user);
    done(null,user);
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
            console.log("Login Successful");
            user.getToken();
            return done(null, user);
        }
    })

}));

//step5 call



app.post('/login', function(req, res, next) {
    passport.authenticate('login', function(err, user) {
        if (!user) { return res.send(null); }
        if(user){
            return res.send(user);
        }
    })(req, res, next);
});

app.get('/home',isLoggedIn,(req,res)=>{
    console.log('success');
    console.log(req.isAuthenticated());
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
                    var token = userdata.getToken();
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


app.post('/signup', function(req, res, next) {
    passport.authenticate('signup', function(err, user) {
        if (!user) { return res.send(null); }
        if(user){
            return res.send(user);
        }
    })(req, res, next);
});

app.get('/find',isLoggedIn,(req,res)=>{
   User.find().then(
       (data)=>{
           res.json(data);
       }
   )
});


app.get('/index',(req,res) => {
    res.sendFile(__dirname + '/views/login.html');
});

app.get('/profile',isLoggedIn,function(req,res){
    console.log("profile");
    res.send('Profile');
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
    res.redirect('/');
}

app.get('/',(req,res)=>{
    res.send("home");
});

app.get('/logout',isLoggedIn,(req,res)=>{
    req.session.destroy();
    req.logout();
    res.redirect('/index');
});

app.get('/private',isLoggedIn, (req, res) => {
        res.send("Welcome");
});

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


// app.post('/login', function(req, res, next) {
//     passport.authenticate('local', function(err, user, info) {
//         if (err) { return next(err); }
//         if (!user) { return res.redirect('/login'); }
//         req.logIn(user, function(err) {
//             if (err) { return next(err); }
//             return res.redirect('/users/' + user.username);
//         });
//     })(req, res, next);
// });


