const crypto = require('crypto');
const fs = require('fs');
const process = require('process');

const AppleStrategy = require('@nicokaiser/passport-apple').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const GoogleStrategy = require('passport-google-oauth20');
const OtpStrategy = require('@ladjs/passport-otp-strategy').Strategy;
const _ = require('lodash');
const isSANB = require('is-string-and-not-blank');
const validator = require('validator');
const { KoaPassport } = require('koa-passport');
const { boolean } = require('boolean');

const PASSPORT_FIELDS = {
  lastLoginField: 'last_login_at',

  displayName: 'display_name',
  givenName: 'given_name',
  familyName: 'family_name',
  avatarURL: 'avatar_url',
  // apple
  appleProfileID: 'apple_profile_id',
  appleAccessToken: 'apple_access_token',
  appleRefreshToken: 'apple_refresh_token',
  // google
  googleProfileID: 'google_profile_id',
  googleAccessToken: 'google_access_token',
  googleRefreshToken: 'google_refresh_token',
  // github
  githubProfileID: 'github_profile_id',
  githubAccessToken: 'github_access_token',
  githubRefreshToken: 'github_refresh_token',
  // otp
  otpToken: 'otp_token',
  otpEnabled: 'otp_enabled'
};

const PASSPORT_PHRASES = {
  INVALID_USER: 'Invalid user response, please try again.',
  INVALID_PROFILE_RESPONSE:
    'Invalid profile response, please delete this site from your third-party sign-in preferences and try again.',
  INVALID_EMAIL:
    'Invalid email address, please delete this site from your third-party sign-in preferences and try again.',
  INVALID_PROFILE_ID:
    'Invalid profile identifier, please delete this site from your third-party sign-in preferences and try again.',
  CONSENT_REQUIRED:
    'Offline access consent required to generate a new refresh token.',
  OTP_NOT_ENABLED: 'OTP authentication is not enabled.',
  OTP_TOKEN_DOES_NOT_EXIST: 'OTP token does not exist for validation.'
};

class Passport extends KoaPassport {
  constructor(config = {}, Users) {
    super();

    this.getEmailFromProfile = this.getEmailFromProfile.bind(this);
    this.loginOrCreateProfile = this.loginOrCreateProfile.bind(this);
    this.updateAndSaveUser = this.updateAndSaveUser.bind(this);

    this.config = _.defaultsDeep(config, {
      providers: {
        local: boolean(process.env.AUTH_LOCAL_ENABLED),
        apple: boolean(process.env.AUTH_APPLE_ENABLED),
        google: boolean(process.env.AUTH_GOOGLE_ENABLED),
        github: boolean(process.env.AUTH_GITHUB_ENABLED),
        otp: boolean(process.env.AUTH_OTP_ENABLED)
      },
      strategies: {
        apple: {
          clientID: process.env.APPLE_CLIENT_ID,
          teamID: process.env.APPLE_TEAM_ID,
          keyID: process.env.APPLE_KEY_ID,
          key: isSANB(process.env.APPLE_KEY_PATH)
            ? fs.readFileSync(process.env.APPLE_KEY_PATH)
            : process.env.APPLE_KEY_PATH,
          callbackURL: process.env.APPLE_CALLBACK_URL,
          scope: ['name', 'email']
        },
        google: {
          clientID: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          callbackURL: process.env.GOOGLE_CALLBACK_URL,
          scope: [
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
          ]
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
      fields: PASSPORT_FIELDS,
      phrases: PASSPORT_PHRASES
    });

    if (_.isObject(Users) && _.isFunction(Users.findOne)) {
      this.serializeUser((user, done) => {
        done(null, user.id);
      });

      this.deserializeUser((id, done) => {
        Users.findOne({ id }, (err, user) => {
          if (err) return done(err);
          // if no user exists then invalidate the previous session
          // <https://github.com/jaredhanson/passport/issues/6#issuecomment-4857287>
          done(null, user ? user : false);
        });
      });

      if (this.config.providers.local) {
        if (!_.isFunction(Users.createStrategy))
          throw new Error(
            'Local strategy configured but Users.createStrategy method is missing'
          );
        this.use(Users.createStrategy());
      }

      // apple
      if (this.config.providers.apple)
        this.use(
          new AppleStrategy(
            this.config.strategies.apple,
            this.loginOrCreateProfile(Users, 'apple')
          )
        );

      // github
      if (this.config.providers.github)
        this.use(
          new GitHubStrategy(
            this.config.strategies.github,
            this.loginOrCreateProfile(Users, 'github')
          )
        );

      // google
      if (this.config.providers.google)
        this.use(
          new GoogleStrategy(
            this.config.strategies.google,
            this.loginOrCreateProfile(Users, 'google')
          )
        );
    }

    // otp
    if (this.config.providers.otp) {
      // validate first factor auth enabled
      const enabledFirstFactor = Object.keys(this.config.providers).filter(
        (provider) =>
          (provider !== 'otp' && this.config.providers[provider] === 'true') ||
          this.config.providers[provider] === true
      );

      if (enabledFirstFactor.length <= 1)
        throw new Error('No first factor authentication strategy enabled');

      this.use(
        new OtpStrategy(this.config.strategies.otp, (user, done) => {
          // if otp is not enabled
          if (!user[this.config.fields.otpEnabled])
            return done(new Error(this.config.phrases.OTP_NOT_ENABLED));

          // we already have the user object from initial login
          if (!user[this.config.fields.otpToken])
            return done(
              new Error(this.config.phrases.OTP_TOKEN_DOES_NOT_EXIST)
            );

          done(null, user[this.config.fields.otpToken]);
        })
      );
    }
  }

  getEmailFromProfile(provider, profile) {
    if (
      provider === 'apple' &&
      _.isString(profile.email) &&
      validator.isEmail(profile.email)
    )
      return profile.email;
    if (!_.isArray(profile.emails)) return;
    const match = profile.emails.find(
      (obj) =>
        _.isObject(obj) && _.isString(obj.value) && validator.isEmail(obj.value)
    );
    if (match) return match.value;
  }

  loginOrCreateProfile(Users, provider) {
    return (accessToken, refreshToken, profile, done) => {
      if (!_.isObject(profile))
        return done(new Error(this.config.phrases.INVALID_PROFILE_RESPONSE));

      if (!isSANB(profile.id))
        return done(new Error(this.config.phrases.INVALID_PROFILE_ID));

      //
      // NOTE: we lookup by profile ID in case the email address changed at the provider
      //
      Users.findOne(
        { [this.config.fields[`${provider}ProfileID`]]: profile.id },
        (err, user) => {
          if (err) return done(err);
          //
          // NOTE: this assumes that the user with that profile ID was not found
          // so we will need to create a new user, but we can only do that
          // if the login profile has a supplied email address
          // and if not, then we need to inform user to revoke authorization
          // for this application and then attempt to sign in again for email retrieval
          // (e.g. "Delete this site from your sign in with $provider preferences")
          // <https://github.com/nicokaiser/passport-apple/issues/3>
          //

          // store a boolean whether we need to save or not
          let save = false;

          // parse the email from the profile
          const email = this.getEmailFromProfile(provider, profile);

          // continue along
          if (user)
            return this.updateAndSaveUser(
              provider,
              accessToken,
              refreshToken,
              profile,
              save,
              user,
              email,
              done
            );

          // this will get the first match (but is dummy-proof)
          if (!email) return done(new Error(this.config.phrases.INVALID_EMAIL));

          //
          // find or create the new user
          //
          Users.findOne({ email }, (err, user) => {
            if (err) return done(err);
            if (!user) {
              user = new Users({
                email,
                [this.config.fields[`${provider}ProfileID`]]: profile.id
              });
              save = true;
            }

            // continue along
            this.updateAndSaveUser(
              provider,
              accessToken,
              refreshToken,
              profile,
              save,
              user,
              email,
              done
            );
          });
        }
      );
    };
  }

  // eslint-disable-next-line complexity, max-params
  updateAndSaveUser(
    provider,
    accessToken,
    refreshToken,
    profile,
    save,
    user,
    email,
    done
  ) {
    //
    // update or set user name and photo
    //
    // (but only if `save` was already true, e.g. first sign in)
    // (we don't want to update user's info if they deleted it)
    // (and then they sign in again and it's auto-repopulated)
    //
    if (save) {
      //
      // name
      //
      if (provider === 'apple') {
        // profile.name = { firstName, lastName }
        if (_.isObject(profile.name)) {
          if (isSANB(profile.name.firstName))
            user[this.config.fields.givenName] = profile.name.firstName;
          if (isSANB(profile.name.lastName))
            user[this.config.fields.familyName] = profile.name.lastName;
        }
      } else {
        //
        // google and github strategies respect this naming convention
        // (we don't want to override values if they were already set though)
        //
        for (const key of ['displayName', 'givenName', 'familyName']) {
          if (isSANB(profile[key]) && !isSANB(user[this.config.fields[key]]))
            user[this.config.fields[key]] = profile[key];
        }

        //
        // google photo
        // (we don't want to override values if they were already set though)
        //
        if (
          provider === 'google' &&
          (!_.isString(user[this.config.fields.avatarURL]) ||
            !validator.isURL(user[this.config.fields.avatarURL])) &&
          _.isObject(profile._json) &&
          _.isObject(profile._json.image) &&
          _.isString(profile._json.image.url) &&
          validator.isURL(profile._json.image.url)
        ) {
          // we don't want ?sz= in the image URL
          user[this.config.fields.avatarURL] =
            profile._json.image.url.split('?sz=')[0];
        }

        //
        // github photo
        // (we don't want to override values if they were already set though)
        //
        if (provider === 'github') {
          const photoMatch = _.isArray(profile.photos)
            ? profile.photos.find(
                (photo) =>
                  _.isObject(photo) &&
                  _.isString(photo.value) &&
                  validator.isURL(photo.value)
              )
            : false;

          if (
            (!_.isString(user[this.config.fields.avatarURL]) ||
              !validator.isURL(user[this.config.fields.avatarURL])) &&
            photoMatch
          )
            user[this.config.fields.avatarURL] = photoMatch.value;
        }
      }
    }

    //
    // handle edge case in which email was not set but we had a profile
    // (this would only happen for users that had profile.id set but no email)
    // (e.g. some accidental delete of the user.email field)
    //
    if (!user.email && email) {
      save = true;
      user.email = email;
    }

    // update or set access token
    if (
      isSANB(accessToken) &&
      user[this.config.fields[`${provider}AccessToken`]] !== accessToken
    ) {
      save = true;
      user[this.config.fields[`${provider}AccessToken`]] = accessToken;
    }

    // update or set refresh token
    if (
      isSANB(refreshToken) &&
      user[this.config.fields[`${provider}RefreshToken`]] !== refreshToken
    ) {
      save = true;
      user[this.config.fields[`${provider}RefreshToken`]] = refreshToken;
    }

    // update or set profile.id (in the rare edge case it could have changed)
    if (user[this.config.fields[`${provider}ProfileID`]] !== profile.id) {
      save = true;
      user[this.config.fields[`${provider}ProfileID`]] = profile.id;
    }

    // update the last login for the user (matches passport-local-mongoose behavior)
    if (this.config.fields.lastLoginField) {
      save = true;
      user[this.config.fields.lastLoginField] = new Date();
    }

    //
    // NOTE: below we have some logic next to comments that say
    //       "support google consent issue" and this is related to a bug
    //       that doesn't let us revoke tokens in order for us to get a new refresh token
    //       (see <http://stackoverflow.com/a/18578660>)
    //       so what we do is explicitly send them to a google URL with `prompt=consent`
    //       (see the Lad codebase for an example of this and the redirect to /auth/google/consent)
    //       (if and only if the `err.consent_required` property exists and is truthy)
    //

    //
    // we only want to call save if it was a new user or if there were actual changes
    // otherwise this is a useless db operation and affects performance
    //
    if (!save) {
      //
      // support google consent issue
      //
      if (provider === 'google' && !isSANB(refreshToken)) {
        const err = new Error(this.config.phrases.CONSENT_REQUIRED);
        err.consent_required = true;
        return done(err);
      }

      return done(null, user.toObject());
    }

    user.save((err, user) => {
      if (err) return done(err);
      //
      // dummy-proofing
      //
      if (!user) return done(new Error(this.config.phrases.INVALID_USER));

      //
      // support google consent issue
      //
      if (provider === 'google' && !isSANB(refreshToken)) {
        const err = new Error(this.config.phrases.CONSENT_REQUIRED);
        err.consent_required = true;
        return done(err);
      }

      done(null, user.toObject());
    });
  }
}

Passport.DEFAULT_PHRASES = PASSPORT_PHRASES;
Passport.DEFAULT_FIELDS = PASSPORT_FIELDS;

module.exports = Passport;
