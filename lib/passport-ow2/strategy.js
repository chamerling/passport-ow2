/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The OW2 authentication strategy authenticates requests by delegating to
 * OW2 using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your OW2 application's Client ID
 *   - `clientSecret`  your OW2 application's Client Secret
 *   - `callbackURL`   URL to which OW2 will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request.  valid scopes include:
 *                     'user', 'public_repo', 'repo', or none.
 *                     (see http://developer.ow2.org/v1/oauth/#scopes for more info)
 *
 * Examples:
 *
 *     passport.use(new OW2Strategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/ow2/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://ow2.org/login/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://ow2.org/login/oauth/access_token';
  options.profileURL = options.profileURL || 'https://api.ow2.org/user';
  options.scopeSeparator = options.scopeSeparator || ',';
  
  OAuth2Strategy.call(this, options, verify);
  this.name = 'ow2';
  this.options = options;
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from OW2.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `ow2`
 *   - `id`               the user's OW2 ID
 *   - `username`         the user's OW2 username
 *   - `displayName`      the user's full name
 *   - `emails`           the user's email addresses
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  
  // issue here, _oauth2.get sets the access_token as bearer token in both the request and as HTTP Header
  // the RFC specifies that the client MUST use only the token in one place
  // the passport-bearer module on the server send back an error!
  // use getProtectedResource which does not add the header
  this._oauth2.getProtectedResource(this.options.profileURL, accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile from OW2', err)); }
    
    try {
      var json = JSON.parse(body);
      
      var profile = { provider: 'ow2' };
      profile.id = json.id;
      profile.displayName = json.name;
      profile.username = json.username;
      
      profile._raw = body;
      profile._json = json;
      
      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
