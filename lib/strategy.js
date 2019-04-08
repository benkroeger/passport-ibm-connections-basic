/* eslint-disable prefer-template,no-param-reassign,no-underscore-dangle,no-unused-vars,no-var,vars-on-top */

'use strict';

var http = require('http');
var https = require('https');

var util = require('util');

var passport = require('passport-strategy');
var _ = require('lodash');
var Profile = require('./profile');

var requestSchemas = {
  http,
  https,
};

function lookup(obj, field) {
  if (!obj) {
    return null;
  }
  var chain = field
    .split(']')
    .join('')
    .split('[');
  for (var i = 0, len = chain.length; i < len; i += 1) {
    var prop = obj[chain[i]];
    if (typeof prop === 'undefined') {
      return null;
    }
    if (typeof prop !== 'object') {
      return prop;
    }
    obj = prop;
  }
  return null;
}

/**
 * `Strategy` constructor.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function IBMConnectionsStrategy(options, verify) {
  var self = this;
  if (typeof options === 'function') {
    verify = options;
    options = {};
  }
  if (!verify) {
    throw new TypeError('IBMConnectionsStrategy requires a verify callback');
  }

  passport.Strategy.call(this);

  options = _.merge(
    {
      usernameField: 'username',
      passwordField: 'password',
      passReqToCallback: false,
      skipUserProfile: false,
      authSchema: 'https',
      authHostname: false,
      authPort: 443,
      openSocial: '/connections',
      authMethod: 'GET',
      defaultRequestHeaders: {
        'user-agent': 'Mozilla/5.0',
      },
    },
    options,
  );

  if (!options.authHostname) {
    throw new TypeError('IBMConnectionsStrategy required a hostname');
  }

  _.forOwn(options, function iterateOptions(val, key) {
    self['_' + key] = val;
  });

  self.name = 'ibm-connections-basic';
  self._verify = verify;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(IBMConnectionsStrategy, passport.Strategy);

// create the final verified function that get's called after "verify" was successful
function getVerfiedFunction(self) {
  return function verified(err, user, info) {
    if (err) {
      // verification occurred and error
      self.error(err);
      return;
    }
    if (!user) {
      // no error happened, but also no user was found during verification
      self.fail(info);
      return;
    }
    // good to go!
    self.success(user, info);
  };
}

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
IBMConnectionsStrategy.prototype.authenticate = function authenticate(
  req,
  options,
) {
  if (!req._passport) {
    this.error(new Error('passport.initialize() middleware not in use'));
    return;
  }
  options = options || {};

  // var paused = options.pauseStream ? pause(req) : null;
  // user does not have an authenticated session or _skipOnReqIsAuthenticated was set to "false"
  var self = this;
  var authReqHeaders = _.merge({}, self._defaultRequestHeaders);
  // get username and password from the request
  var username =
    lookup(req.body, this._usernameField) ||
    lookup(req.query, this._usernameField);
  var password =
    lookup(req.body, this._passwordField) ||
    lookup(req.query, this._passwordField);

  options = _.merge({}, options);

  var authReqHttpOptions = {
    hostname: this._authHostname,
    port: this._authPort,
    path: this._openSocial + '/opensocial/basic/rest/people/@me/@self',
    method: this._authMethod,
    headers: authReqHeaders,
  };

  var completeRequestURI = util.format(
    '%s://%s%s',
    this._authSchema,
    this._authHostname,
    authReqHttpOptions.path,
  );

  // if we were able to find username and password in the original request, attach them to authentication-request as BASIC-AUTH header
  if (username && password) {
    authReqHttpOptions.auth = util.format('%s:%s', username, password);
  }
  var authReq = requestSchemas[this._authSchema].request(
    authReqHttpOptions,
    function handleAuthResponse(authRes) {
      authRes.setEncoding('utf8');
      if (authRes.statusCode === 401) {
        self.fail('Wrong credentials', 401);
        return;
      }
      if (authRes.statusCode === 200) {
        var authResBody = '';

        // collect the data chunks
        authRes.on('data', function onData(chunk) {
          authResBody += chunk;
        });

        authRes.on('end', function onEnd() {
          try {
            var json;
            try {
              json = JSON.parse(authResBody);
            } catch (ex) {
              self.error(new Error('Failed to parse user profile'));
              return;
            }

            var profile = Profile.parse(json);
            profile.provider = self.name;

            if (self._passReqToCallback) {
              self._verify(
                req,
                profile,
                authRes.headers['set-cookie'],
                completeRequestURI,
                getVerfiedFunction(self),
              );
            } else {
              self._verify(
                profile,
                authRes.headers['set-cookie'],
                completeRequestURI,
                getVerfiedFunction(self),
              );
            }
          } catch (ex) {
            self.error(ex);
          }
        });
      } else {
        self.error(authRes.statusCode);
      }
    },
  );

  authReq.on('error', function onError(e) {
    return self.error(e);
  });

  // write data to request body
  authReq.write('\n');
  authReq.write('\n');
  authReq.end();
};

/**
 * Expose `Strategy`.
 */
module.exports = IBMConnectionsStrategy;
