
const jwt = require('jsonwebtoken');

const controllers = require('../controllers');
const libs = require('../lib');
const config = require('../config/configVars');

/**
 * 
 * @param {boolean} condition 
 * @returns {import('../@types/global').RequestHandler1}
 */
const checkLogin = (condition) => {
    return (req,  res, next) => {
        try {
            const isLoggedIn  = (req?.session?.userId)?true:false;
            if ( isLoggedIn === condition ) return next();
            if (!req?.session?.userId) {
                throw new Error(libs.messages.errorMessage.sessionExpired);
            }
            if (!req.session?.userId) {
                return res.status(401).json({error: libs.messages.errorMessage.sessionExpired})
            }
            return res.status(403).json({error: libs.messages.errorMessage.genericMessage});
        } catch (error) {
            console.log(error);
            return res.status(500).json({error: error?.message ?? error});
        }
    }
}

/**
 * 
 * @param {import('express').Request} req 
 * @param {import('express').Response} res 
 * @param {() =>  void} next 
 * @returns 
 */
const populateSession = async (req, res, next) => {
    try {
        const sKey = req.cookies.jwt ?? req.body.authToken;
        req.isAuthenticated = false;
        req.session = {};
        if (sKey) {
            delete req.body.authToken;
            const sessionObj  = await controllers.authController.authenticateSession(sKey);
            if (sessionObj) {
                req.isAuthenticated = true;
                req.session = sessionObj;
                return next();
            }
        }
        
        const lKey = req.cookies.ljwt;
        if (lKey) {
            const userData = jwt.verify(lKey, libs.constants.jwtSecret);
            const {email} = userData;
            console.log(userData);
            const [token] = await controllers.authController.login({email}, true);
            if (!token) throw new Error('Token not present');
            res.cookie('jwt', token, config.sessionCookieConfig);
            const sessionObj = await controllers.authController.authenticateSession(token);
            if (!sessionObj) throw new Error('Session obj not present');
            req.isAuthenticated = true;
            req.session = sessionObj;
        }

        return next();
    } catch (error) {
        console.log(error);
        req.isAuthenticated = false;
        req.session = {};
        res.clearCookie('jwt');
        res.clearCookie('ljwt');
        return next();
    }
}

module.exports = {
    checkLogin,
    populateSession,
}


// chnage 
// const jwt = require('jsonwebtoken');
// const controllers = require('../controllers');
// const libs = require('../lib');
// const config = require('../config/configVars');

// /**
//  * Middleware to check user authentication status.
//  * @param {boolean} condition - Expected login state (true = logged in, false = logged out).
//  * @returns {import('express').RequestHandler}
//  */
// const checkLogin = (condition) => {
//     return (req, res, next) => {
//         try {
//             // Check if user is logged in
//             const isLoggedIn = !!req?.session?.userId;

//             // If login state matches the condition, proceed
//             if (isLoggedIn === condition) return next();

//             // Session expired: Clear cookies and send error response
//             if (!isLoggedIn) {
//                 res.clearCookie('jwt');
//                 res.clearCookie('ljwt');
//                 return res.status(401).json({
//                     error: libs.messages.errorMessage.sessionExpired,
//                 });
//             }

//             // Unauthorized
//             return res.status(403).json({
//                 error: libs.messages.errorMessage.genericMessage,
//             });
//         } catch (error) {
//             console.error('Session Error:', error);
//             return res.status(500).json({
//                 error: error.message || 'Internal Server Error',
//             });
//         }
//     };
// };

// /**
//  * Middleware to populate session from JWT or long-term JWT.
//  * @param {import('express').Request} req
//  * @param {import('express').Response} res
//  * @param {import('express').NextFunction} next
//  */
// const populateSession = async (req, res, next) => {
//     try {
//         // Ensure cookies are properly set and are of the correct type
//         const sKey = typeof req.cookies?.jwt === 'string' ? req.cookies.jwt : req.body.authToken;
//         const lKey = typeof req.cookies?.ljwt === 'string' ? req.cookies.ljwt : null;

//         req.isAuthenticated = false;
//         req.session = {};

//         // Check and authenticate short-term JWT session
//         if (sKey) {
//             delete req.body.authToken;
//             const sessionObj = await controllers.authController.authenticateSession(sKey);
//             if (sessionObj) {
//                 req.isAuthenticated = true;
//                 req.session = sessionObj;
//                 return next();
//             }
//         }

//         // Authenticate long-term JWT session (if available)
//         if (lKey) {
//             const userData = jwt.verify(lKey, libs.constants.jwtSecret);
//             const { email } = userData;

//             const [token] = await controllers.authController.login({ email }, true);
//             if (!token) throw new Error('Token generation failed.');

//             res.cookie('jwt', token, config.sessionCookieConfig);
//             const sessionObj = await controllers.authController.authenticateSession(token);
//             if (!sessionObj) throw new Error('Session object creation failed.');

//             req.isAuthenticated = true;
//             req.session = sessionObj;
//         }

//         return next();
//     } catch (error) {
//         console.error('Error populating session:', error);
//         req.isAuthenticated = false;
//         req.session = {};
//         res.clearCookie('jwt');
//         res.clearCookie('ljwt');
//         return next();
//     }
// };


// module.exports = {
//     checkLogin,
//     populateSession,
// };
