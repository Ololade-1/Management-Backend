const asyncHandler = require('express-async-handler');
const User = require('../models/usermodel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Token = require('../models/tokenmodel');
const crypto = require('crypto');
const sendemail = require('../utils/sendemail');

// Generate Token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

// Register users
const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !password || !email) {
        throw new Error('Please fill in all required fields');
    }
    if (password.length < 6 || password.length > 20) {
        throw new Error('Password must be between 6 and 20 characters long');
    }

    // Check if user email already exists
    const userExists = await User.findOne({ email });

    if (userExists) {
        throw new Error('Email has already been registered');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = await User.create({
        name,
        email,
        password: hashedPassword,
    });

    // Generate Token
    const token = generateToken(newUser._id);

    // Send HTTP-only cookie
    res.cookie('token', token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400),
        sameSite: "none",
        secure: true
    });

    if (newUser) {
        const { _id, name, email, photo, phone, bio } = newUser;
        res.status(201).json({
            _id,
            name,
            email,
            photo,
            phone,
            bio,
            token,
        });
    } else {
        throw new Error('Invalid user data');
    }
});

// Login user
const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Validate request
    if (!email || !password) {
        return res.status(400).json({ error: 'Please provide email and password' });
    }

    // Check if user exists
    const user = await User.findOne({ email });

    if (!user) {
        return res.status(404).json({ error: 'User not found. Please sign up.' });
    }

    // User exists, check if password is correct
    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    if (passwordIsCorrect) {
        const token = generateToken(user._id);

        // Send HTTP-only cookie
        res.cookie('token', token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400),
            sameSite: "none",
            secure: true
        });

        const { _id, name, email, photo, phone, bio } = user;
        res.status(200).json({
            _id,
            name,
            email,
            photo,
            phone,
            bio,
            token,
        });
    } else {
        return res.status(400).json({ error: 'Invalid email or password' });
    }
});

// Logout user
const logout = asyncHandler(async (req, res) => {
    res.clearCookie('token', {
        path: "/",
        httpOnly: true,
        expires: new Date(0),
        sameSite: "none",
        secure: true,
    });
    return res.status(200).json({ message: "Successfully logged out" });
});

// Get user profile
const getuser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id); // Corrected function name to findById
    if (user) {
        const { _id, name, email, photo, phone, bio } = user;
        res.status(200).json({
            _id,
            name,
            email,
            photo,
            phone,
            bio,
        });
    } else {
        throw new Error('User not found');
    }
});

// Get logged in status
const loggedin = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json(false);
    }
    // Verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    if (verified) {
        return res.json(true);
    }
    return res.json(false);
});

// Update user
const updateuser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);
    if (user) {
        const { name, email, photo, phone, bio } = user;
        user.email = email;
        user.name = req.body.name || name;
        user.phone = req.body.phone || phone;
        user.photo = req.body.photo || photo;
        user.bio = req.body.bio || bio;

        const updatedUser = await user.save();
        res.status(200).json({
            _id: updatedUser._id,
            name: updatedUser.name,
            email: updatedUser.email,
            photo: updatedUser.photo,
            phone: updatedUser.phone,
            bio: updatedUser.bio,
        });
    } else {
        res.status(404);
        throw new Error('User not found');
    }
});

// Change password
const changepassword = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    const { oldpassword, password } = req.body;
    if (!user) {
        res.status(400);
        throw new Error('User not found, please sign up');
    }

    // Validate
    if (!oldpassword || !password) {
        res.status(400);
        throw new Error('Please add old and new password');
    }

    // Check if old password matches password in DB
    const passwordIsCorrect = await bcrypt.compare(oldpassword, user.password);

    // Save new password
    if (user && passwordIsCorrect) {
        user.password = password;
        await user.save();
        res.status(200).send('Password change successful');
    } else {
        res.status(400);
        throw new Error('Old password is incorrect');
    }
});

// Forgot password
const forgotpassword = asyncHandler(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        res.status(404);
        throw new Error('User does not exist');
    }

    //delete token if it exist in db

    let token = await Token.findOne({userid: user._id})
    if(token){
        await Token.deleteOne()
    }

    // Create reset token
    const resetToken = crypto.randomBytes(32).toString('hex') + user._id;
    console.log(resetToken);

    // Hash token before saving to DB
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  
        //save token to db

        await new Token({
            userid: user._id,
            token: hashedToken,
            createdAt: Date.now(),
            expiresAt: Date.now()+ 30*(60*1000) // 30 minutes
        }).save()

        //construct reset url

        const reseturl =`${process.env.FRONTEND_URL}/restpassword/${resetToken}`

        // reset email

        const message = `
        <h1>Hello ${user.name}</h1>
        <p>please use the url below to reset your password</p>
        <p> This reet link is valid for only 30 minutes. </p>

            <a href=${reseturl} clicktracking=off>${reseturl}</a>

        <p>Regards...</p>
        <p>Ololade Team</p>`;

        const subject ="password reset request"
        const  send_to = user.email
        const sent_from = process.env.EMAIL_USER

        try {
            await sendemail(subject, message, send_to,sent_from)
            res.status(200).json({success: true, message:'rest email sent'})
        } catch (error) {
            res.status(500)
            throw new Error('email not sent, please try again')
        }
});

// reset password

const resetpassword = asyncHandler(async(req, res)=>{
const {password}=req.body
const {resettoken}= req.params

//hash token,then compare to token in database

    const hashedtoken = crypto
    .createHash('sha256')
    .update(resettoken)
    .digest('hex');

    //find token in database

    const usertoken = await Token.findOne({
        token: hashedtoken,
        expiresAt:{$gt:Date.now()}
    })

    if(!usertoken){
        res.status(404);
        throw new Error('invalid or expired token');
    }

    //find user

    const user = await User.findOne({_id: usertoken.userid})
    user.password =password
    await user.save()

    res.status(200).json({message:'password reset successful, please login'});
})


module.exports = { registerUser, 
    loginUser, logout, getuser, loggedin,
     updateuser, changepassword, forgotpassword, resetpassword };
