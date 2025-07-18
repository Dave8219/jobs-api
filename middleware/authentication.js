const User = require('../models/User');
const jwt = require('jsonwebtoken');
const {UnauthenticatedError} = require('../errors');



const auth = async (req, res, next) => {
// check header

const authHeader = req.headers.authorization;
if (!authHeader || !authHeader.startsWith('Bearer ')) {
throw new UnauthenticatedError('Authentication Failed');
}
const token = authHeader.split(' ')[1];

try {
const payload = jwt.verify(token, process.env.JWT_SECRET)
// attach the user to the job routes

/*
// this code looks for the user in the database - takes the user model and find by ID and remove the password to include only the userId - this is alternative to just creating the object like below
const user = User.findById(payload.id).select('-password');
req.user = user;
*/

// creating an object
req.user = {userId: payload.userId, name: payload.name};
next();
}
catch (error) {
throw new UnauthenticatedError('Authentication Invalid');
}
}


module.exports = auth;
