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

exports.validate_token = function(req, res){
  let validate = authService.Validate(req.body.token,function(err, result){
      if(err) res.send(err.message);
      res.send(result);
  })
};
