const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Please add a name'],
    },
    email: {
        type: String,
        required: [true, 'Please add an email'],
        unique: true,
        trim: true, 
        match: [
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
            'please enter a valid email'
        ]
    },
    password: {
        type: String,
        required: [true, 'Please add a password'],
        minlength: [6, 'Password must be at least 6 characters long'],
    },
    photo:{
        type: String,
        required: [true, 'Please add a photo'],
        default: 'http://i.co/4pDNDK1/avatar.png'
    },
    phone:{
        type: String,
        maxlength: [20, 'Phone number must not be more than 20 characters'],  
        default: '+234'
    },
    bio:{
        type: String,
        maxlength: [250, 'Bio must not be more than 250 characters'],  
        default: 'bio'
    }
}, {
    timestamps:true,
});

//encrypt the password before saving to Db
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) {
        return next();
    }

    // hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(this.password, salt);
    this.password = hashedPassword;
    next();
});

const User = mongoose.model('User', userSchema);

module.exports = User;
