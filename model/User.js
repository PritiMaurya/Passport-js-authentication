const {mongoose} = require('../db/mongoose');
const validate = require('mongoose-validator');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
var emailValidator =
    validate({
        validator: 'isEmail',
        message: "{VALUE} is not valid email"
    });
var passValidator = validate({
    validator: 'isLength',
    args: [8,16],
    message: "Password length should be 8 to 16"
})
const userSchema = new mongoose.Schema({
    name:{
        type: String,
        trim: true
    },
    mobile:{
        type: String,
        trim: true
    },
    password:{
        type: String,
        trim: true
    },
    email:{
        type:  String,
        validate: emailValidator,
        trim: true
    },
    gender:{
        type: String,
        trim: true
    },
    pic:{
        type: String,
        trim: true
    },
    token: {
        access: String,
        token: String
    }
});


userSchema.methods.getToken= function () {
    //console.log("token data");
    user1 = this;
    var access = 'auth';
    token1 = jwt.sign({_id: user1._id.toHexString(),access},"priti7878").toString();
    user1.token.access = access;
    user1.token.token = token1;
    //console.log(user1.token);
    return user1.save().then(
        ()=>{
            return token1;
        }
    );
}


var User = mongoose.model('user', userSchema);

module.exports ={
    User
}

