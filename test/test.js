const LocalStrategy = require('passport-local');
const test = require('ava');
const { KoaPassport } = require('koa-passport');

const Passport = require('..');

test('errors if Users is not an object', (t) => {
  t.throws(() => new Passport(null, {}), {
    message: 'Users object not defined'
  });
});

test('exposes config object', (t) => {
  const pass = new Passport({});
  t.true(pass instanceof KoaPassport);
  t.is(typeof pass.config, 'object');
  t.is(typeof pass.config.serializeUser, 'function');
  t.is(typeof pass.config.deserializeUser, 'function');
  t.is(typeof pass.serializeUser, 'function');
  t.is(typeof pass.deserializeUser, 'function');
  t.is(typeof pass.use, 'function');
  t.is(typeof pass.config.providers, 'object');
  t.is(typeof pass.config.strategies, 'object');
  t.is(typeof pass.config.google, 'object');
  t.is(typeof pass.config.github, 'object');
  t.is(typeof pass.config.fields, 'object');
});

test('creates passport object with no configs', (t) => {
  const pass = new Passport({}, {});

  t.is(typeof pass, 'object');
});

test('serializeUser > returns user.id', (t) => {
  t.plan(2);

  const pass = new Passport({}, {});

  pass.serializeUser({ id: '1' }, (err, id) => {
    t.is(err, null);
    t.is(id, '1');
  });
});

test('deserializeUser > returns user', async (t) => {
  t.plan(2);

  const user = { id: '1' };
  const Users = {
    findOne: () => Promise.resolve(user)
  };

  const pass = new Passport(Users, {});

  await pass.deserializeUser('1', (err, ret) => {
    t.is(err, null);
    t.is(ret, user);
  });
});

test('deserializeUser > returns error', async (t) => {
  t.plan(2);

  const pass = new Passport({}, {});

  await pass.deserializeUser('1', (err, user) => {
    t.is(typeof err, 'object');
    t.is(typeof user, 'undefined');
  });
});

test('deserializeUser > errors if no user', async (t) => {
  t.plan(2);

  const Users = {
    findOne: () => Promise.resolve(false)
  };

  const pass = new Passport(Users, {});

  await pass.deserializeUser('1', (err, ret) => {
    t.is(err, null);
    t.is(ret, false);
  });
});

test('create local strategy', (t) => {
  const Users = {
    createStrategy: () =>
      new LocalStrategy(function (username, password, done) {
        done(null, true);
      })
  };

  const pass = new Passport(Users, {
    providers: { local: true }
  });

  t.is(typeof pass._strategies.local, 'object');
});

test('test github strategy', async (t) => {
  t.plan(14);

  const toObject = function () {
    return this;
  };

  let Users = {
    findOne: () =>
      Promise.resolve({
        save: () => Promise.resolve(),
        toObject
      })
  };

  let pass = new Passport(Users, {
    providers: { github: true },
    strategies: {
      github: {
        clientID: 'test',
        clientSecret: 'thisSecret',
        callbackURL: 'localhost'
      }
    }
  });

  t.is(typeof pass._strategies.github, 'object');

  await pass._strategies.github._verify(
    null,
    null,
    {
      emails: [{ value: 'test' }],
      displayName: 'robert',
      givenName: 'frost',
      familyName: 'jack',
      photos: [{ value: 'http://www.example.com' }]
    },
    (err, user) => {
      t.is(err, null);
      t.is(typeof user, 'object');
      t.is(user.display_name, 'robert');
      t.is(user.given_name, 'frost');
      t.is(user.family_name, 'jack');
      t.is(user.avatar_url, 'http://www.example.com');
    }
  );

  Users = function () {
    return {
      avatar_url: 'http://www.example.com',
      save: () => Promise.resolve(),
      toObject
    };
  };

  Users.findOne = () => Promise.resolve();

  pass = new Passport(Users, {
    providers: { github: true },
    strategies: {
      github: {
        clientID: 'test',
        clientSecret: 'thisSecret',
        callbackURL: 'localhost'
      }
    }
  });

  await pass._strategies.github._verify(
    'access',
    'refresh',
    {
      id: 'id',
      emails: [{ value: 'test@example.com' }]
    },
    (err, user) => {
      t.is(err, null);
      t.is(typeof user, 'object');
      t.is(user.github_profile_id, 'id');
      t.is(user.github_access_token, 'access');
      t.is(user.github_refresh_token, 'refresh');
    }
  );

  await pass._strategies.github._verify(null, null, null, (err, user) => {
    t.is(typeof err, 'object');
    t.is(typeof user, 'undefined');
  });
});

test.serial('test google strategy', async (t) => {
  t.plan(17);

  const toObject = function () {
    return this;
  };

  let Users = {
    findOne: () => Promise.resolve({ save: () => Promise.resolve(), toObject })
  };

  let pass = new Passport(Users, {
    providers: { google: true },
    strategies: {
      google: {
        clientID: 'test',
        clientSecret: 'thisSecret',
        callbackURL: 'localhost'
      }
    }
  });

  t.is(typeof pass._strategies.google, 'object');

  await pass._strategies.google._verify(
    null,
    false,
    {
      emails: [{ value: 'test@example.com' }],
      _json: {
        image: {
          url: 'www.example.com'
        }
      }
    },
    (err, user) => {
      t.is(err.message, 'Consent required');
      t.is(typeof user, 'undefined');
    }
  );

  await pass._strategies.google._verify(
    null,
    'refresh',
    {
      id: '1',
      emails: [{ value: 'test@example.com' }],
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
      t.is(err, null);
      t.is(typeof user, 'object');
      t.is(user.google_profile_id, '1');
      t.is(user.display_name, 'lord_byron');
      t.is(user.given_name, 'lord');
      t.is(user.family_name, 'byron');
      t.is(user.avatar_url, 'www.example.com');
    }
  );

  Users = function () {
    return {
      avatar_url: 'www.example.com',
      save: () => Promise.resolve(),
      toObject
    };
  };

  Users.findOne = () => Promise.resolve();

  pass = new Passport(Users, {
    providers: { google: true },
    strategies: {
      google: {
        clientID: 'test',
        clientSecret: 'thisSecret',
        callbackURL: 'localhost'
      }
    }
  });

  await pass._strategies.google._verify(
    'access',
    'refresh',
    {
      id: 'id',
      emails: [{ value: 'test@example.com' }]
    },
    (err, user) => {
      t.is(err, null);
      t.is(typeof user, 'object');
      t.is(user.google_profile_id, 'id');
      t.is(user.google_access_token, 'access');
      t.is(user.google_refresh_token, 'refresh');
    }
  );

  await pass._strategies.google._verify(null, null, null, (err, user) => {
    t.is(typeof err, 'object');
    t.is(typeof user, 'undefined');
  });
});

test('test otp strategy', (t) => {
  t.plan(7);

  t.throws(() => new Passport({}, { providers: { otp: true } }), {
    message: 'No first factor authentication strategy enabled'
  });

  const pass = new Passport({}, { providers: { otp: true, local: true } });

  pass._strategies.otp._setup({ otp_enabled: false }, (err, user) => {
    t.is(err.message, 'OTP authentication is not enabled');
    t.is(typeof user, 'undefined');
  });

  pass._strategies.otp._setup(
    { otp_enabled: true, otp_token: false },
    (err, user) => {
      t.is(err.message, 'OTP token does not exist for validation');
      t.is(typeof user, 'undefined');
    }
  );

  pass._strategies.otp._setup(
    { otp_enabled: true, otp_token: '1' },
    (err, otpToken) => {
      t.is(err, null);
      t.is(otpToken, '1');
    }
  );
});
