// global.fetch = require('node-fetch');
// global.navigator = () => null;
//
// const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
// const AWS = require("aws-sdk");
//
// AWS.config.update({accessKeyId: 'AKIAW6X7TRHQNQJ4ZDZL', secretAccessKey: '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'});
//
//
// const pool_region = "us-east-1";
//
// // const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
//
// const cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider({region: "us-east-1"});
//
// exports.Register = async function (body, callback) {
//   // const name = body.name;
//   // const email = body.email;
//   // const password = body.password;
//   // const attributeList = [];
//
//   const params = {
//     UserPoolId: "us-east-1_II1skHYh3",
//     Username: "desyatkov@gmail.com",
//     DesiredDeliveryMediums: ["EMAIL"],
//     ForceAliasCreation: false,
//     MessageAction: "SUPPRESS",
//     TemporaryPassword: 'Abc1234567!',
//     UserAttributes: [
//       { Name: "given_name", Value: "sergey" },
//       { Name: "family_name", Value: "desyatkov"},
//       { Name: "name", Value: "sergey desyatkov"},
//       { Name: "email", Value: "desyatkov@gmail.com"},
//     ],
//   };
//
//   await cognitoIdentityServiceProvider.adminCreateUser(params, function(error, data) {
//     if (error) {
//         console.log("Error adding user to cognito: " + error, error.stack);
//         callback(error);
//       } else {
//         console.log(data);
//         const cognitoUser = data.User;
//         callback(null, cognitoUser);
//       }
//   });
//
//
//
//
//   // attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({
//   //   Name: "email",
//   //   Value: email
//   // }));
//   // userPool.signUp(name, password, attributeList, null, function (err, result) {
//   //   if (err)
//   //     callback(err);
//   //   var cognitoUser = result.user;
//   //   callback(null, cognitoUser);
//   // })
// };
//
// exports.Login = function (body, callback) {
//   var userName = body.name;
//   var password = body.password;
//   var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
//     Username: userName,
//     Password: password
//   });
//   var userData = {
//     Username: userName,
//     Pool: userPool
//   }
//   var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
//   cognitoUser.authenticateUser(authenticationDetails, {
//     onSuccess: function (result) {
//       var accesstoken = result.getAccessToken().getJwtToken();
//       callback(null, accesstoken);
//     },
//     onFailure: (function (err) {
//       callback(err);
//     })
//   })
// };
//
// exports.Validate = function (token, callback) {
//   request({
//     url: `https://cognito-idp.${pool_region}.amazonaws.com/${poolData.UserPoolId}/.well-known/jwks.json`,
//     json: true
//   }, function (error, response, body) {
//     if (!error && response.statusCode === 200) {
//       pems = {};
//       var keys = body['keys'];
//       for (var i = 0; i < keys.length; i++) {
//         var key_id = keys[i].kid;
//         var modulus = keys[i].n;
//         var exponent = keys[i].e;
//         var key_type = keys[i].kty;
//         var jwk = {
//           kty: key_type,
//           n: modulus,
//           e: exponent
//         };
//         var pem = jwkToPem(jwk);
//         pems[key_id] = pem;
//       }
//       var decodedJwt = jwt.decode(token, {
//         complete: true
//       });
//       if (!decodedJwt) {
//         console.log("Not a valid JWT token");
//         callback(new Error('Not a valid JWT token'));
//       }
//       var kid = decodedJwt.header.kid;
//       var pem = pems[kid];
//       if (!pem) {
//         console.log('Invalid token');
//         callback(new Error('Invalid token'));
//       }
//       jwt.verify(token, pem, function (err, payload) {
//         if (err) {
//           console.log("Invalid Token.");
//           callback(new Error('Invalid token'));
//         } else {
//           console.log("Valid Token.");
//           callback(null, "Valid token");
//         }
//       });
//     } else {
//       console.log("Error! Unable to download JWKs");
//       callback(error);
//     }
//   });
// };
