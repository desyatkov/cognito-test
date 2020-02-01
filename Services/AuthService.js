require('dotenv').config();
const aws = require('aws-sdk');
const {isEmpty} = require('lodash');
const request = require('request');
const jwkToPem = require('jwk-to-pem');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

aws.config.update({
    region: process.env.COGNITO_POOL_REGION,
    accessKeyId: process.env.ACCESS_KEY_ID,
    secretAccessKey: process.env.SECRET_ACCESS_KEY
});

async function signUp(params) {
    const {
        username,
        email,
        password,
        name,
        fName
    } = params;

    try {
        const cognito = new aws.CognitoIdentityServiceProvider();

        await cognito.adminCreateUser({
            UserPoolId: process.env.USER_POOL_ID,
            Username: username || email,
            MessageAction: 'SUPPRESS',
            TemporaryPassword: password,
            UserAttributes: [
                {Name: 'given_name', Value: name},
                {Name: 'family_name', Value: fName},
                {Name: 'name', Value: `${name} ${fName}`},
                {Name: 'email', Value: email},
                {Name: 'email_verified', Value: 'true'}
            ],
        }).promise();

        const initAuthResponse = await cognito.adminInitiateAuth({
            AuthFlow: 'ADMIN_NO_SRP_AUTH',
            ClientId: process.env.CLIENT_ID,
            UserPoolId: process.env.USER_POOL_ID,
            AuthParameters: {
                USERNAME: email,
                PASSWORD: password
            }
        }).promise();

        if (initAuthResponse.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
            return await cognito.adminRespondToAuthChallenge({
                ChallengeName: 'NEW_PASSWORD_REQUIRED',
                ClientId: process.env.CLIENT_ID,
                UserPoolId: process.env.USER_POOL_ID,
                ChallengeResponses: {
                    USERNAME: email,
                    NEW_PASSWORD: password,
                },
                Session: initAuthResponse.Session
            }).promise();
        }

    } catch (err) {
        throw err
    }
}

exports.Register = async function (body, callback) {
    signUp(body.userData).then(data => {
        callback(null, data);
    }).catch(err => {
        callback(err);
    })
};

async function login({email, password}) {
    try {
        const cognito = new aws.CognitoIdentityServiceProvider();
        return await cognito.adminInitiateAuth({
            AuthFlow: 'ADMIN_NO_SRP_AUTH',
            ClientId: process.env.CLIENT_ID,
            UserPoolId: process.env.USER_POOL_ID,
            AuthParameters: {
                USERNAME: email,
                PASSWORD: password
            }
        }).promise()
    } catch (err) {
        throw err
    }
}

exports.Login = function (body, callback) {
    login(body).then(data => {
        callback(null, data);
    }).catch(err => {
        callback(err);
    })
};

const resetPassword = async ({email}) => {
    try {
        const cognito = new aws.CognitoIdentityServiceProvider();
        return await cognito.adminResetUserPassword({
            UserPoolId: process.env.USER_POOL_ID,
            Username: email
        }).promise()
    } catch (err) {
        throw err
    }
};

const confirmResetPassword = async ({confirmationCode, email, newPassword}) => {
    try {
        const params = {
            ClientId: process.env.CLIENT_ID,
            ConfirmationCode: confirmationCode,
            Password: newPassword,
            Username: email
        };

        const cognito = new aws.CognitoIdentityServiceProvider();
        const confirmReset = await cognito.confirmForgotPassword(params).promise()

        if (isEmpty(confirmReset)) {
            return await cognito.adminSetUserPassword({
                Password: newPassword,
                UserPoolId: process.env.USER_POOL_ID,
                Username: email,
                Permanent: true
            }).promise();
        }

        return confirmReset
    } catch (err) {
        throw err
    }
};

exports.ResetPassword = function (body, callback) {
    resetPassword(body).then(data => {
        callback(null, data);
    }).catch(err => {
        callback(err);
    })
};

exports.confirmResetPassword = function (body, callback) {
    confirmResetPassword(body).then(data => {
        callback(null, data);
    }).catch(err => {
        callback(err);
    })
};

const adminGetUser = async ({username}) => {
    try {
        const cognito = new aws.CognitoIdentityServiceProvider();
        return await cognito.adminGetUser({
            UserPoolId: process.env.USER_POOL_ID,
            Username: username
        }).promise()
    } catch (err) {
        throw err
    }
};

exports.adminGetUser = function (body, callback) {
    adminGetUser(body).then(data => {
        callback(null, data);
    }).catch(err => {
        callback(err);
    })
};



exports.Validate = function(token, callback){
    request({
        url : `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_II1skHYh3/.well-known/jwks.json`,
        json : true
    }, function(error, response, body){
        if (!error && response.statusCode === 200) {
            let pems = {};
            const keys = body['keys'];
            for(let i = 0; i < keys.length; i++) {
                const key_id = keys[i].kid;
                const modulus = keys[i].n;
                const exponent = keys[i].e;
                const key_type = keys[i].kty;
                const jwk = { kty: key_type, n: modulus, e: exponent};
                pems[key_id] = jwkToPem(jwk);;
            }
            const decodedJwt = jwt.decode(token, {complete: true});

            if (!decodedJwt) {
                console.log("Not a valid JWT token");
                callback(new Error('Not a valid JWT token'));
            }
            const kid = decodedJwt.header.kid;
            const pem = pems[kid];

            if (!pem) {
                console.log('Invalid token');
                callback(new Error('Invalid token'));
            }

            jwt.verify(token, pem, function(err, payload) {
                if(err) {
                    console.log("Invalid Token.");
                    callback(new Error('Invalid token'));
                } else {
                    console.log("Valid Token.");
                    callback(null, "Valid token");
                }
            });

        } else {
            console.log("Error! Unable to download JWKs");
            callback(error);
        }
    });
};

const hashUserAccountId = ({ clientId, sub }) =>
    crypto
        .createHash('md5')
        .update(`${clientId}:${sub}`)
        .digest('hex');

const mapCognitoUserObject = userData =>
    userData.UserAttributes.reduce((acc, { Name, Value }) => ({ ...acc, [Name]: Value }), {
        username: userData.Username,
    });

const getProfileFromCookie = ({ reqFieldName, jwtSecret, cookieFieldName }, logger) => req => {
    try {
        req[reqFieldName] =
            req.signedCookies &&
            req.signedCookies[cookieFieldName] &&
            jwt.verify(req.signedCookies[cookieFieldName], jwtSecret);
    } catch (error) {
        logger.error(`Error validating/setting req.${reqFieldName} from client cookie (jwt)`);
    }
    if (!req[reqFieldName]) req[reqFieldName] = null;
};

const setProfileToCookie = ({ cookieFieldName, jwtSecret, cookieOptions }) => ({ res, user }) => {
    res.cookie(cookieFieldName, jwt.sign(user, jwtSecret), cookieOptions);
};

const getUser = async ({AuthenticationResult}) => {
    try {
        const { AccessToken } = AuthenticationResult;
        const cognito = new aws.CognitoIdentityServiceProvider();
        const userData = await cognito.getUser({AccessToken}).promise();
        const { client_id: clientId, sub } = jwt.decode(AccessToken);

        return { userAccountId: hashUserAccountId({ clientId, sub }), ...mapCognitoUserObject(userData) };

    } catch (err) {
        throw err
    }
};



exports.LoginAccess = function (body, callback) {
    login(body)
        .then(async userTokenData => ({
            user: await getUser(userTokenData),
            userTokenData
        })).then(({ user }) => {
            callback(null, { user });
            // const cookieConfig = { cookieFieldName, jwtSecret, cookieOptions, reqFieldName };
            // setProfileToCookie(cookieConfig)({ res, user, userTokenData });
        }).catch(err => {
            callback(err);
        })
};
