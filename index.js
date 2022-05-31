const crypto = require('crypto');
const process = require('process');

const GitHubStrategy = require('passport-github2').Strategy;
const OtpStrategy = require('@ladjs/passport-otp-strategy').Strategy;
const _ = require('lodash');
const validator = require('validator');
const { KoaPassport } = require('koa-passport');
const { OAuth2Strategy } = require('passport-google-oauth');
const { boolean } = require('boolean');

class Passport extends KoaPassport {
  constructor(Users, config = {}) {
    super();

    if (!_.isObject(Users)) throw new Error('Users object not defined');

    this.config = _.defaultsDeep(config, {
      serializeUser(user, done) {
        done(null, user.id);
      },
      async deserializeUser(id, done) {
        try {
          const user = await Users.findOne({ id });
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
            step: 30,
            // allow last and current totp passcode
            window: 1
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

    this.serializeUser(this.config.serializeUser);
    this.deserializeUser(this.config.deserializeUser);

    if (this.config.providers.local && _.isFunction(Users.createStrategy))
      this.use(Users.createStrategy());

    if (this.config.providers.github)
      this.use(
        new GitHubStrategy(
          this.config.strategies.github,
          async (accessToken, refreshToken, profile, done) => {
            try {
              const email = profile.emails[0].value;

              let user = await Users.findOne({ email });
              if (!user) user = new Users({ email });
              for (const key of ['displayName', 'givenName', 'familyName']) {
                if (!user[this.config.fields[key]] && profile[key])
                  user[this.config.fields[key]] = profile[key];
              }

              user[this.config.fields.githubProfileID] = profile.id;
              user[this.config.fields.githubAccessToken] = accessToken;
              user[this.config.fields.githubRefreshToken] = refreshToken;

              if (
                (!_.isString(user[this.config.fields.avatarURL]) ||
                  !validator.isURL(user[this.config.fields.avatarURL])) &&
                _.isArray(profile.photos) &&
                !_.isEmpty(profile.photos) &&
                _.isObject(profile.photos[0]) &&
                _.isString(profile.photos[0].value) &&
                validator.isURL(profile.photos[0].value)
              )
                user[this.config.fields.avatarURL] = profile.photos[0].value;

              await user.save();

              done(null, user.toObject());
            } catch (err) {
              done(err);
            }
          }
        )
      );

    if (this.config.providers.google)
      this.use(
        new OAuth2Strategy(
          this.config.strategies.google,
          async (accessToken, refreshToken, profile, done) => {
            try {
              const email = profile.emails[0].value;

              let user = await Users.findOne({ email });
              if (!user) user = new Users({ email });
              for (const key of ['displayName', 'givenName', 'familyName']) {
                if (!user[this.config.fields[key]] && profile[key])
                  user[this.config.fields[key]] = profile[key];
              }

              user[this.config.fields.googleProfileID] = profile.id;
              user[this.config.fields.googleAccessToken] = accessToken;
              user[this.config.fields.googleRefreshToken] = refreshToken;

              if (
                (!_.isString(user[this.config.fields.avatarURL]) ||
                  !validator.isURL(user[this.config.fields.avatarURL])) &&
                _.isObject(profile._json.image) &&
                _.isString(profile._json.image.url) &&
                validator.isURL(profile._json.image.url)
              ) {
                // we don't want ?sz= in the image URL
                user[this.config.fields.avatarURL] =
                  profile._json.image.url.split('?sz=')[0];
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

    if (this.config.providers.otp) {
      // validate first factor auth enabled
      const enabledFirstFactor = Object.keys(this.config.providers).filter(
        (provider) => {
          return (
            (provider !== 'otp' &&
              this.config.providers[provider] === 'true') ||
            this.config.providers[provider] === true
          );
        }
      );

      if (enabledFirstFactor.length <= 1)
        throw new Error('No first factor authentication strategy enabled');

      this.use(
        new OtpStrategy(this.config.strategies.otp, (user, done) => {
          // if otp is not enabled
          if (!user[this.config.fields.otpEnabled])
            return done(new Error('OTP authentication is not enabled'));

          // we already have the user object from initial login
          if (!user[this.config.fields.otpToken])
            return done(new Error('OTP token does not exist for validation'));

          done(null, user[this.config.fields.otpToken]);
        })
      );
    }
  }
}

module.exports = Passport;
