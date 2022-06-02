const LocalStrategy = require('passport-local');
const test = require('ava');
const { KoaPassport } = require('koa-passport');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

const Passport = require('..');

const obj = {};
for (const value of Object.values(Passport.DEFAULT_FIELDS)) {
  obj[value] = String;
}

const User = new mongoose.Schema({
  id: String,
  email: String,
  ...obj
});

User.pre('validate', function (next) {
  this.id = this._id.toString();
  next();
});

const Users = mongoose.model('User', User);
const server = new MongoMemoryServer();

test.before(async () => {
  await server.start();
  await mongoose.connect(server.getUri());
});

test.after(async () => {
  await server.stop();
});

test('exposes config object', (t) => {
  const passport = new Passport({}, Users);
  t.true(passport instanceof KoaPassport);
  t.is(typeof passport.config, 'object');
  t.is(typeof passport.serializeUser, 'function');
  t.is(typeof passport.deserializeUser, 'function');
  t.is(typeof passport.use, 'function');
  t.is(typeof passport.config.providers, 'object');
  t.is(typeof passport.config.strategies, 'object');
  t.is(typeof passport.config.strategies.apple, 'object');
  t.is(typeof passport.config.strategies.google, 'object');
  t.is(typeof passport.config.strategies.github, 'object');
  t.is(typeof passport.config.strategies.otp, 'object');
  t.is(typeof passport.config.fields, 'object');
  t.is(typeof passport.config.phrases, 'object');
});

test('creates passport object with no configs', (t) => {
  const passport = new Passport();
  t.is(typeof passport, 'object');
});

test('serializeUser > returns user.id', async (t) => {
  const passport = new Passport({}, Users);

  const id = await new Promise((resolve, reject) => {
    passport.serializeUser({ id: '1' }, (err, id) => {
      if (err) return reject(err);
      resolve(id);
    });
  });
  t.is(id, '1');
});

test('deserializeUser > returns user', async (t) => {
  const user = await Users.create({});

  const passport = new Passport({}, Users);

  const result = await new Promise((resolve, reject) => {
    passport.deserializeUser(user.id, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    });
  });
  t.deepEqual(result.toObject(), user.toObject());
});

test('deserializeUser > returns error', async (t) => {
  const passport = new Passport(
    {},
    {
      findOne(query, fn) {
        fn(new Error('Oops!'));
      }
    }
  );

  const err = await t.throwsAsync(
    new Promise((resolve, reject) => {
      passport.deserializeUser(null, (err, user) => {
        if (err) return reject(err);
        resolve(user);
      });
    })
  );
  t.is(err.message, 'Oops!');
});

test('deserializeUser > returns false if no user', async (t) => {
  const passport = new Passport({}, Users);

  const result = await new Promise((resolve, reject) => {
    passport.deserializeUser('1', (err, ret) => {
      if (err) return reject(err);
      resolve(ret);
    });
  });
  t.is(result, false);
});

test('create local strategy', (t) => {
  Users.createStrategy = () => {
    return new LocalStrategy(function (username, password, done) {
      done(null, true);
    });
  };

  const passport = new Passport(
    {
      providers: { local: true }
    },
    Users
  );

  t.is(typeof passport._strategies.local, 'object');
});

test('create local strategy throws error if method missing', (t) => {
  const err = t.throws(() => {
    return new Passport(
      {
        providers: { local: true }
      },
      {
        findOne() {}
      }
    );
  });
  t.regex(err.message, /method is missing/);
});

test('test apple strategy', async (t) => {
  let passport = new Passport(
    {
      providers: { apple: true },
      strategies: {
        apple: {
          clientID: 'test',
          teamID: 'test',
          keyID: 'test',
          key: 'test',
          clientSecret: 'thisSecret',
          callbackURL: 'localhost'
        }
      }
    },
    Users
  );

  t.is(typeof passport._strategies.apple, 'object');

  {
    const user = await new Promise((resolve, reject) => {
      passport._strategies.apple._verify(
        null,
        null,
        {
          id: '3',
          email: 'test-apple@apple.com',
          name: {
            firstName: 'jack',
            lastName: 'frost'
          }
        },
        (err, user) => {
          if (err) return reject(err);
          resolve(user);
        }
      );
    });

    t.is(typeof user, 'object');
    t.is(user.email, 'test-apple@apple.com');
    t.is(user.given_name, 'jack');
    t.is(user.family_name, 'frost');
  }

  passport = new Passport(
    {
      providers: { apple: true },
      strategies: {
        apple: {
          clientID: 'test',
          teamID: 'test',
          keyID: 'test',
          key: 'test',
          clientSecret: 'thisSecret',
          callbackURL: 'localhost'
        }
      }
    },
    Users
  );

  {
    const user = await new Promise((resolve, reject) => {
      passport._strategies.apple._verify(
        'access',
        'refresh',
        {
          id: '4',
          email: 'test-1@example.com'
        },
        (err, user) => {
          if (err) return reject(err);
          resolve(user);
        }
      );
    });
    t.is(typeof user, 'object');
    t.is(user.apple_profile_id, '4');
    t.is(user.apple_access_token, 'access');
    t.is(user.apple_refresh_token, 'refresh');
  }

  const err = await t.throwsAsync(
    new Promise((resolve, reject) => {
      passport._strategies.apple._verify(null, null, null, (err, user) => {
        if (err) return reject(err);
        resolve(user);
      });
    })
  );
  t.is(err.message, passport.config.phrases.INVALID_PROFILE_RESPONSE);
});

test('test github strategy', async (t) => {
  let passport = new Passport(
    {
      providers: { github: true },
      strategies: {
        github: {
          clientID: 'test',
          clientSecret: 'thisSecret',
          callbackURL: 'localhost'
        }
      }
    },
    Users
  );

  t.is(typeof passport._strategies.github, 'object');

  {
    const user = await new Promise((resolve, reject) => {
      passport._strategies.github._verify(
        null,
        null,
        {
          id: '3',
          emails: [{ value: 'test-github@github.com' }],
          displayName: 'robert',
          givenName: 'frost',
          familyName: 'jack',
          photos: [{ value: 'http://www.example.com' }]
        },
        (err, user) => {
          if (err) return reject(err);
          resolve(user);
        }
      );
    });

    t.is(typeof user, 'object');
    t.is(user.email, 'test-github@github.com');
    t.is(user.display_name, 'robert');
    t.is(user.given_name, 'frost');
    t.is(user.family_name, 'jack');
    t.is(user.avatar_url, 'http://www.example.com');
  }

  passport = new Passport(
    {
      providers: { github: true },
      strategies: {
        github: {
          clientID: 'test',
          clientSecret: 'thisSecret',
          callbackURL: 'localhost'
        }
      }
    },
    Users
  );

  {
    const user = await new Promise((resolve, reject) => {
      passport._strategies.github._verify(
        'access',
        'refresh',
        {
          id: '4',
          emails: [{ value: 'test-1@example.com' }]
        },
        (err, user) => {
          if (err) return reject(err);
          resolve(user);
        }
      );
    });
    t.is(typeof user, 'object');
    t.is(user.github_profile_id, '4');
    t.is(user.github_access_token, 'access');
    t.is(user.github_refresh_token, 'refresh');
  }

  const err = await t.throwsAsync(
    new Promise((resolve, reject) => {
      passport._strategies.github._verify(null, null, null, (err, user) => {
        if (err) return reject(err);
        resolve(user);
      });
    })
  );
  t.is(err.message, passport.config.phrases.INVALID_PROFILE_RESPONSE);
});

test.serial('test google strategy', async (t) => {
  let passport = new Passport(
    {
      providers: { google: true },
      strategies: {
        google: {
          clientID: 'test',
          clientSecret: 'thisSecret',
          callbackURL: 'localhost'
        }
      }
    },
    Users
  );

  t.is(typeof passport._strategies.google, 'object');

  {
    const err = await t.throwsAsync(
      new Promise((resolve, reject) => {
        passport._strategies.google._verify(
          null,
          false,
          {
            id: '5',
            emails: [{ value: 'test-2@example.com' }],
            _json: {
              image: {
                url: 'www.example.com'
              }
            }
          },
          (err, user) => {
            if (err) return reject(err);
            resolve(user);
          }
        );
      })
    );
    t.is(err.message, passport.config.phrases.CONSENT_REQUIRED);
    t.true(err.consent_required);
  }

  {
    const user = await new Promise((resolve, reject) => {
      passport._strategies.google._verify(
        null,
        'refresh',
        {
          id: '1',
          emails: [{ value: 'test-3@example.com' }],
          _json: {
            image: {
              url: 'www.example.com?sz=test'
            }
          },
          displayName: 'lord_byron',
          givenName: 'lord',
          familyName: 'byron'
        },
        (err, user) => {
          if (err) return reject(err);
          resolve(user);
        }
      );
    });
    t.is(typeof user, 'object');
    t.is(user.google_profile_id, '1');
    t.is(user.display_name, 'lord_byron');
    t.is(user.given_name, 'lord');
    t.is(user.family_name, 'byron');
    t.is(user.avatar_url, 'www.example.com');
  }

  passport = new Passport(
    {
      providers: { google: true },
      strategies: {
        google: {
          clientID: 'test',
          clientSecret: 'thisSecret',
          callbackURL: 'localhost'
        }
      }
    },
    Users
  );

  {
    const user = await new Promise((resolve, reject) => {
      passport._strategies.google._verify(
        'access',
        'refresh',
        {
          id: '7',
          emails: [{ value: 'test-4@example.com' }]
        },
        (err, user) => {
          if (err) return reject(err);
          resolve(user);
        }
      );
    });
    t.is(typeof user, 'object');
    t.is(user.google_profile_id, '7');
    t.is(user.google_access_token, 'access');
    t.is(user.google_refresh_token, 'refresh');
  }

  {
    const err = await t.throwsAsync(
      new Promise((resolve, reject) => {
        passport._strategies.google._verify(null, null, null, (err, user) => {
          if (err) return reject(err);
          resolve(user);
        });
      })
    );
    t.is(err.message, passport.config.phrases.INVALID_PROFILE_RESPONSE);
  }
});

test('test otp strategy', async (t) => {
  t.throws(() => new Passport({ providers: { otp: true } }), {
    message: 'No first factor authentication strategy enabled'
  });

  const passport = new Passport({ providers: { otp: true, local: true } });

  {
    const err = await t.throwsAsync(
      new Promise((resolve, reject) => {
        passport._strategies.otp._setup({ otp_enabled: false }, (err, user) => {
          if (err) return reject(err);
          resolve(user);
        });
      })
    );
    t.is(err.message, 'OTP authentication is not enabled.');
  }

  {
    const err = await t.throwsAsync(
      new Promise((resolve, reject) => {
        passport._strategies.otp._setup(
          { otp_enabled: true, otp_token: false },
          (err, user) => {
            if (err) return reject(err);
            resolve(user);
          }
        );
      })
    );
    t.is(err.message, 'OTP token does not exist for validation.');
  }

  {
    const otpToken = await new Promise((resolve, reject) => {
      passport._strategies.otp._setup(
        { otp_enabled: true, otp_token: '1' },
        (err, otpToken) => {
          if (err) return reject(err);
          resolve(otpToken);
        }
      );
    });
    t.is(otpToken, '1');
  }
});
