# @ladjs/passport

[![build status](https://github.com/ladjs/passport/actions/workflows/ci.yml/badge.svg)](https://github.com/ladjs/passport/actions/workflows/ci.yml)
[![code style](https://img.shields.io/badge/code_style-XO-5ed9c7.svg)](https://github.com/sindresorhus/xo)
[![styled with prettier](https://img.shields.io/badge/styled_with-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![made with lass](https://img.shields.io/badge/made_with-lass-95CC28.svg)](https://lass.js.org)
[![license](https://img.shields.io/github/license/ladjs/passport.svg)](LICENSE)

> Passport for Lad


## Table of Contents

* [Install](#install)
* [Usage](#usage)
* [Strategies](#strategies)
* [Options](#options)
* [Contributors](#contributors)
* [License](#license)


## Install

[npm][]:

```sh
npm install @ladjs/passport
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

const passport = new Passport({}, Users);

const app = new Koa();
app.use(passport.initialize());
app.use(passport.session());
```


## Strategies

Currently supported strategies:

* Local (email)
* Apple (Sign in with Apple)
* GitHub
* Google
* OTP


## Options

See [index.js](index.js) for configuration defaults and environment flags.

You can customize the field names and phrases, see the `fields` and `phrases` objects in [index.js](index.js).


## Contributors

| Name             | Website                           |
| ---------------- | --------------------------------- |
| **Nick Baugh**   | <http://niftylettuce.com/>        |
| **Shaun Warman** | <https://shaunwarman.com/>        |
| **shadowgate15** | <https://github.com/shadowgate15> |


## License

[MIT](LICENSE) © [Nick Baugh](http://niftylettuce.com/)


##

[npm]: https://www.npmjs.com/
