const crypto = require('crypto');

const GitHubStrategy = require('passport-github2').Strategy;
const OtpStrategy = require('passport-otp-strategy').Strategy;
const _ = require('lodash');
const passport = require('koa-passport');
const validator = require('validator');
const { OAuth2Strategy } = require('passport-google-oauth');
const { boolean } = require('boolean');

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
      google: boolean(process.env.AUTH_GOOGLE_ENABLED),
      github: boolean(process.env.AUTH_GITHUB_ENABLED),
      otp: boolean(process.env.AUTH_OTP_ENABLED)
    },
    strategies: {
      google: {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL
      },
      github: {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: process.env.GITHUB_CALLBACK_URL,
        scope: ['user:email']
      },
      otp: {
        codeField: process.env.OTP_CODE_FIELD || 'passcode',
        // `authenticator` options passed through to `otplib`
        // <https://github.com/yeojz/otplib>
        authenticator: {
          crypto,
          step: 30
        }
      }
    },
    google: {
      accessType: 'offline',
      prompt: 'consent',
      scope: [
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile'
      ]
    },
    github: {
      scope: ['user:email']
    },
    fields: {
      displayName: 'display_name',
      givenName: 'given_name',
      familyName: 'family_name',
      avatarURL: 'avatar_url',
      googleProfileID: 'google_profile_id',
      googleAccessToken: 'google_access_token',
      googleRefreshToken: 'google_refresh_token',
      githubProfileID: 'github_profile_id',
      githubAccessToken: 'github_access_token',
      githubRefreshToken: 'github_refresh_token',
      otpToken: 'otp_token',
      otpEnabled: 'otp_enabled'
    }
  });

  const { fields } = config;

  passport.serializeUser(config.serializeUser);
  passport.deserializeUser(config.deserializeUser);

  if (config.providers.local && _.isFunction(Users.createStrategy))
    passport.use(Users.createStrategy());

  if (config.providers.github)
    passport.use(
      new GitHubStrategy(
        config.strategies.github,
        async (accessToken, refreshToken, profile, done) => {
          try {
            const email = profile.emails[0].value;

            let user = await Users.findOne({ email });
            if (!user) user = new Users({ email });
            ['displayName', 'givenName', 'familyName'].forEach(key => {
              if (!user[fields[key]] && profile[key])
                user[fields[key]] = profile[key];
            });

            user[fields.githubProfileID] = profile.id;
            user[fields.githubAccessToken] = accessToken;
            user[fields.githubRefreshToken] = refreshToken;

            if (
              (!_.isString(user[fields.avatarURL]) ||
                !validator.isURL(user[fields.avatarURL])) &&
              _.isArray(profile.photos) &&
              !_.isEmpty(profile.photos) &&
              _.isObject(profile.photos[0]) &&
              _.isString(profile.photos[0].value) &&
              validator.isURL(profile.photos[0].value)
            )
              user[fields.avatarURL] = profile.photos[0].value;

            await user.save();

            done(null, user.toObject());
          } catch (err) {
            done(err);
          }
        }
      )
    );

  if (config.providers.google)
    passport.use(
      new OAuth2Strategy(
        config.strategies.google,
        async (accessToken, refreshToken, profile, done) => {
          try {
            const email = profile.emails[0].value;

            let user = await Users.findOne({ email });
            if (!user) user = new Users({ email });
            ['displayName', 'givenName', 'familyName'].forEach(key => {
              if (!user[fields[key]] && profile[key])
                user[fields[key]] = profile[key];
            });

            user[fields.googleProfileID] = profile.id;
            user[fields.googleAccessToken] = accessToken;
            user[fields.googleRefreshToken] = refreshToken;

            if (
              (!_.isString(user[fields.avatarURL]) ||
                !validator.isURL(user[fields.avatarURL])) &&
              _.isObject(profile._json.image) &&
              _.isString(profile._json.image.url) &&
              validator.isURL(profile._json.image.url)
            ) {
              // we don't want ?sz= in the image URL
              user[fields.avatarURL] = profile._json.image.url.split('?sz=')[0];
            }

            await user.save();

            // there is still a bug that doesn't let us revoke tokens
            // in order for us to get a new refresh token per:
            // <http://stackoverflow.com/a/18578660>
            // so instead we explicitly send them to the google url
            // with `prompt=consent` specified (this rarely happens)
            if (!refreshToken) return done(new Error('Consent required'));

            done(null, user.toObject());
          } catch (err) {
            done(err);
          }
        }
      )
    );

  if (config.providers.otp) {
    // validate first factor auth enabled
    const enabledFirstFactor = Object.keys(config.providers).filter(
      provider => {
        return (
          (provider !== 'otp' && config.providers[provider] === 'true') ||
          config.providers[provider] === true
        );
      }
    );

    if (enabledFirstFactor.length === 0)
      throw new Error('No first factor authentication strategy enabled');

    passport.use(
      new OtpStrategy(config.strategies.otp, function(user, done) {
        // if otp is not enabled
        if (!user[fields.otpEnabled])
          return done(new Error('OTP authentication is not enabled'));

        // we already have the user object from initial login
        if (!user[fields.otpToken])
          return done(new Error('OTP token does not exist for validation'));

        done(null, user[fields.otpToken]);
      })
    );
  }

  return passport;
}

module.exports = Passport;
