const jwt = require('jsonwebtoken');
const createError = require('http-errors');
const TokenLogModel = require('@v1/models/token-log-model');

module.exports = {
  validateToken: function ({ token, type = 'token' }) {
    try {
      let result = {};
      let optionSecret = {
        token: process.env.JWT_SECRET_USER,
        refresh: process.env.JWT_SECRET,
        admin: process.env.JWT_SECRET_ADMIN,
      };
      jwt.verify(token, optionSecret[type], async function (err, decoded) {
        if (err) {
          result = { payload: null, err };
        } else {
          result = { payload: decoded };
          if (type === 'refresh') {
            let refreshTokens = JSON.parse(await redis.get(decoded.id.toString())) || [];
            if (!refreshTokens.includes(token)) {
              result = { payload: null, err: createError.Unauthorized() };
            }
          }
        }
      });

      return result;
    } catch (error) {
      console.error(error);
      return createError.Unauthorized(error.message);
    }
  },
  generateToken: async function ({ payload, remember = false, type = 'token' }) {
    try {
      let expiresIn = '2d';
      if (remember) expiresIn = '7d';
      if (type === 'refresh') expiresIn = '90d';
      let optionSecret = {
        token: process.env.JWT_SECRET_USER,
        refresh: process.env.JWT_SECRET,
        admin: process.env.JWT_SECRET_ADMIN,
      };

      let options = { expiresIn };
      let checkTokenLog = await TokenLogModel.findOne({
        userId: payload.id,
        status: true,
      }).sort({
        createdAt: -1,
      });
      if (checkTokenLog) payload.time = checkTokenLog.time;

      let token = jwt.sign(payload, optionSecret[type], options);
      if (type === 'refresh') {
        let refreshTokens = JSON.parse(await redis.get(payload.id.toString())) || [];
        refreshTokens.push(token);
        await redis.set(
          payload.id.toString(),
          JSON.stringify(refreshTokens),
          'EX',
          90 * 24 * 60 * 60,
        );
      }
      return token;
    } catch (error) {
      console.log('redis set token error:::', error);
      return createError.InternalServerError(error);
    }
  },
};
