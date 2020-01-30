cognitoIdentityServiceProvider.adminCreateUser(params, function(error, data) {
    if (error) {
        console.log("Error adding user to cognito: " + error, error.stack);
        callback(error);
    } else {
        console.log(data);
        const cognitoUser = data.User;
        callback(null, cognitoUser);
    }
});
