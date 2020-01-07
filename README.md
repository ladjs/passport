# passport

[![build status](https://img.shields.io/travis/ladjs/passport.svg)](https://travis-ci.org/ladjs/passport)
[![code coverage](https://img.shields.io/codecov/c/github/ladjs/passport.svg)](https://codecov.io/gh/ladjs/passport)
[![code style](https://img.shields.io/badge/code_style-XO-5ed9c7.svg)](https://github.com/sindresorhus/xo)
[![styled with prettier](https://img.shields.io/badge/styled_with-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![made with lass](https://img.shields.io/badge/made_with-lass-95CC28.svg)](https://lass.js.org)
[![license](https://img.shields.io/github/license/ladjs/passport.svg)](LICENSE)

> Passport for Lad


## Table of Contents

* [Install](#install)
* [Usage](#usage)
* [Options](#options)
* [Contributors](#contributors)
* [License](#license)


## Install

[npm][]:

```sh
npm install @ladjs/passport
```

[yarn][]:

```sh
yarn add @ladjs/passport
```


## Usage

```js
const Passport = require('@ladjs/passport');
const koa = require('koa');
const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');

const User = new mongoose.Schema();
User.plugin(passportLocalMongoose, {
  // ...
});
const Users = mongoose.model('User', UserSchema);

const passport = new Passport(Users, {
  // ...
});

const app = new Koa();
app.use(passport.initialize());
app.use(passport.session());
```


## Options

See [index.js](index.js) for configuration defaults and environment flags.

You can customize the field names, see the `fields` object in [index.js](index.js).


## Contributors

| Name             | Website                    |
| ---------------- | -------------------------- |
| **Nick Baugh**   | <http://niftylettuce.com/> |
| **Shaun Warman** | <https://shaunwarman.com/> |


## License

[MIT](LICENSE) © [Nick Baugh](http://niftylettuce.com/)


## 

[npm]: https://www.npmjs.com/

[yarn]: https://yarnpkg.com/
