const express = require('express');
const AuthController = require('@v1/controllers/client/auth-controller');
const router = express.Router();

router.post('/register', AuthController.register);
router.post('/login', AuthController.login);
router.post('/refresh-token', AuthController.token);
router.post('/phone', AuthController.phone);

module.exports = router;
