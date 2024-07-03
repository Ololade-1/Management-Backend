const express = require('express');
const router = express.Router();

const { registerUser, loginUser, logout, getuser, loggedin, updateuser, changepassword, forgotpassword, resetpassword } = require('../controllers/usercontroller');
const protect = require('../middleware/authmiddleware');

router.post('/register', registerUser);
router.post('/login', loginUser);

router.get('/logout', logout);
router.get('/getuser', protect, getuser);
router.get('/loggedin', loggedin);
router.patch('/updateuser', protect, updateuser);
router.patch('/changepassword', protect, changepassword);
router.post('/forgotpassword', forgotpassword);
router.post('/resetpassword/:resettoken', resetpassword);

module.exports = router;
