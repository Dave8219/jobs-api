const User = require('../models/User');
const {StatusCodes} = require('http-status-codes');
const {BadRequestError, UnauthenticatedError} = require('../errors');

// const jwt = require('jsonwebtoken');   MOVED FUNCTIONALITY TO USER.JS **

// const bcrypt = require('bcryptjs');



const register = async (req, res) => {
// res.send('register user');

/* OPTIONAL TO CHECK ERRORS IN THE CONTROLLERS - BUT WILL USE MONGOOSE REGULARLY
const {name, email, password} = req.body;
if (!name || !email || !password) {
throw new BadRequestError('Please provide name, email and password');
}
*/


/*
const {name, email, password} = req.body;
const salt = await bcrypt.genSalt(10);
const hashedPassword = await bcrypt.hash(password, salt);
const tempUser = {name, email, password: hashedPassword};
const user = await User.create({...tempUser});
*/

const user = await User.create({...req.body});

// USED THE JWT SECRET WITH THE GETNAME FUNCTION IN USER.JS - MOVED FUNCTIONALITY TO USER.JS **
// const token = jwt.sign({userId: user._id, name: user.name}, 'jwtSecret', {expiresIn: '30d'});
const token = user.createJWT();

// res.status(StatusCodes.CREATED).json(req.body);   for testing in Postman
// res.status(StatusCodes.CREATED).json({user}); instead of sending back the user like here, next line send back the user

// res.status(StatusCodes.CREATED).json({user: {name: user.name}, token});

// USING JWT WITH A FUNCTION IN THE USER.JS FILE - MOVED FUNCTIONALITY TO USER.JS **
// res.status(StatusCodes.CREATED).json({user: {name: user.getName(), token});  

res.status(StatusCodes.CREATED).json({user: {name: user.name}, token});
}



const login = async (req, res) => {
// res.send('login user');

const {email, password} = req.body;
if (!email || !password) {
throw new BadRequestError('Please provide email and password');
}

const user = await User.findOne({email});

if (!user) {
throw new UnauthenticatedError('Invalid Credentials');
}
const isPasswordCorrect = await user.comparePassword(password);
if (!isPasswordCorrect) {
throw new UnauthenticatedError('Invalid Credentials');
}
// compare password
const token = user.createJWT();
res.status(StatusCodes.OK).json({user: {name: user.name}, token});

}

 
module.exports = {register, login};



