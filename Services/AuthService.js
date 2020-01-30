require('dotenv').config()
const aws = require('aws-sdk');

aws.config.update({
  region: process.env.COGNITO_POOL_REGION,
  accessKeyId: process.env.ACCESS_KEY_ID,
  secretAccessKey: process.env.SECRET_ACCESS_KEY
});

async function signUp(params) {
  const {
    email,
    password,
    name,
    fName
  } = params;

  try {
    const cognito = new aws.CognitoIdentityServiceProvider();

    await cognito.adminCreateUser({
      UserPoolId: process.env.USER_POOL_ID,
      Username: email,
      MessageAction: 'SUPPRESS',
      TemporaryPassword: password,
      UserAttributes: [
        { Name: "given_name", Value: name },
        { Name: "family_name", Value: fName},
        { Name: "name", Value: `${name} ${fName}`},
        { Name: "email", Value: email},
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

exports.Validate = function (token, callback) {};
