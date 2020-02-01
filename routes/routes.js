const express = require('express');
const router = express.Router();
const authController = require('../Controllers/AuthController');

router.post('/auth/register', authController.register);

router.post('/auth/login', authController.login);

router.post('/auth/reset-password', authController.resetPassword);

router.post('/auth/confirm-reset-password', authController.confirmResetPassword);

router.get('/auth/get-user', authController.adminGetUser);

router.post('/auth/validate', authController.validate_token);

router.post('/auth/login-access', authController.loginAccess);

module.exports = router;
