var express = require('express')
  , passport = require('passport')
  , util = require('util')
  , OW2Strategy = require('passport-ow2').Strategy;

var OW2_CLIENT_ID = "--insert-ow2-client-id-here--"
var OW2_CLIENT_SECRET = "--insert-ow2-client-secret-here--";


// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete OW2 profile is serialized
//   and deserialized.
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});


// Use the OW2Strategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and OW2
//   profile), and invoke a callback with a user object.
passport.use(new OW2Strategy({
    clientID: OW2_CLIENT_ID,
    clientSecret: OW2_CLIENT_SECRET,
    callbackURL: "http://127.0.0.1:3000/auth/ow2/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
      
      // To keep the example simple, the user's OW2 profile is returned to
      // represent the logged-in user.  In a typical application, you would want
      // to associate the OW2 account with a user record in your database,
      // and return that user instead.
      return done(null, profile);
    });
  }
));




var app = express.createServer();

// configure Express
app.configure(function() {
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.use(express.logger());
  app.use(express.cookieParser());
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.session({ secret: 'keyboard cat' }));
  // Initialize Passport!  Also use passport.session() middleware, to support
  // persistent login sessions (recommended).
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));
});


app.get('/', function(req, res){
  res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login', function(req, res){
  res.render('login', { user: req.user });
});

// GET /auth/ow2
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in OW2 authentication will involve redirecting
//   the user to ow2.org.  After authorization, OW2 will redirect the user
//   back to this application at /auth/ow2/callback
app.get('/auth/ow2',
  passport.authenticate('ow2'),
  function(req, res){
    // The request will be redirected to OW2 for authentication, so this
    // function will not be called.
  });

// GET /auth/ow2/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/ow2/callback', 
  passport.authenticate('ow2', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

app.listen(3000);


// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login')
}
