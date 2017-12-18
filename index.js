const passport = require('koa-passport');
const _ = require('lodash');
const { OAuth2Strategy } = require('passport-google-oauth');
const boolean = require('boolean');

function Passport(Users, config) {
  if (!_.isObject(Users)) throw new Error('Users object not defined');

  config = _.defaultsDeep(config, {
    serializeUser: (user, done) => {
      done(null, user.email);
    },
    deserializeUser: async (email, done) => {
      try {
        const user = await Users.findOne({ email });
        // if no user exists then invalidate the previous session
        // <https://github.com/jaredhanson/passport/issues/6#issuecomment-4857287>
        if (!user) return done(null, false);
        // otherwise continue along
        done(null, user);
      } catch (err) {
        done(err);
      }
    },
    providers: {
      local: boolean(process.env.AUTH_LOCAL_ENABLED),
      google: boolean(process.env.AUTH_GOOGLE_ENABLED)
      /*
      facebook: boolean(process.env.AUTH_FACEBOOK_ENABLED),
      twitter: boolean(process.env.AUTH_TWITTER_ENABLED),
      github: boolean(process.env.AUTH_GITHUB_ENABLED),
      linkedin: boolean(process.env.AUTH_LINKEDIN_ENABLED),
      instagram: boolean(process.env.AUTH_INSTAGRAM_ENABLED),
      stripe: boolean(process.env.AUTH_STRIPE_ENABLED)
      */
    },
    strategies: {
      google: {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL
      }
      /*
      facebook: {
        clientID: process.env.FACEBOOK_CLIENT_ID,
        clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
        callbackURL: process.env.FACEBOOK_CALLBACK_URL
      },
      twitter: {},
      github: {},
      linkedin: {},
      instagram: {},
      stripe: {}
      */
    },
    google: {
      accessType: 'offline',
      approvalPrompt: 'force',
      scope: [
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile'
      ]
    }
  });

  passport.serializeUser(config.serializeUser);
  passport.deserializeUser(config.deserializeUser);

  if (config.providers.local && _.isFunction(Users.createStrategy))
    passport.use(Users.createStrategy());

  if (config.providers.google)
    passport.use(
      new OAuth2Strategy(
        config.strategies.google,
        async (accessToken, refreshToken, profile, done) => {
          const email = profile.emails[0].value;

          try {
            let user = await Users.findOne({ email });

            if (user) {
              // store the access token and refresh token
              if (accessToken) user.set('google_access_token', accessToken);
              if (refreshToken) user.set('google_refresh_token', refreshToken);
              user = await user.save();
            } else {
              // there is still a bug that doesn't let us revoke tokens
              // in order for us to get a new refresh token per:
              // <http://stackoverflow.com/a/18578660>
              // so instead we explicitly send them to the google url
              // with `prompt=consent` specified (this rarely happens)
              if (!refreshToken) return done(new Error('Consent required'));

              const obj = {
                email,
                display_name: profile.displayName,
                given_name: profile.name.givenName,
                family_name: profile.name.familyName,
                google_profile_id: profile.id,
                google_access_token: accessToken,
                google_refresh_token: refreshToken
              };

              if (
                _.isObject(profile._json.image) &&
                _.isString(profile._json.image.url)
              ) {
                obj.avatar_url = profile._json.image.url;
                // we don't want ?sz= in the image URL
                obj.avatar_url = obj.avatar_url.split('?sz=')[0];
              }

              user = await Users.create(obj);
            }

            done(null, user.toObject());
          } catch (err) {
            done(err);
          }
        }
      )
    );

  return passport;
}

module.exports = Passport;
