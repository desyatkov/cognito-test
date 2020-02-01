const authService = require('../Services/AuthService.js');

exports.register = function(req, res){
    authService.Register(req.body, function(err, result){
        if(err) res.send(err);
        res.send(result);
    })
};

exports.login = function(req, res){
  authService.Login(req.body, function(err, result){
      if(err) res.send(err);
      res.send(result);
  })
};

exports.resetPassword = function(req, res){
  authService.ResetPassword(req.body, function(err, result){
      if(err) res.send(err);
      res.send(result);
  })
};

exports.confirmResetPassword = function(req, res){
  authService.confirmResetPassword(req.body, function(err, result){
      if(err) res.send(err);
      res.send(result);
  })
};

exports.adminGetUser = function(req, res){
  authService.adminGetUser(req.body, function(err, result){
      if(err) res.send(err);
      res.send(result);
  })
};

exports.loginAccess = function(req, res){
  authService.LoginAccess(req.body, function(err, result){
      if(err) res.send(err);
      res.send(result);
  })
};

exports.validate_token = function(req, res){
    authService.Validate(req.body.token,function(err, result){
        if(err)
            res.send(err.message);
        res.send(result);
    })
};
