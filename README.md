# auth

[![build status](https://img.shields.io/travis/ladjs/auth.svg)](https://travis-ci.org/ladjs/auth)
[![code coverage](https://img.shields.io/codecov/c/github/ladjs/auth.svg)](https://codecov.io/gh/ladjs/auth)
[![code style](https://img.shields.io/badge/code_style-XO-5ed9c7.svg)](https://github.com/sindresorhus/xo)
[![styled with prettier](https://img.shields.io/badge/styled_with-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![made with lass](https://img.shields.io/badge/made_with-lass-95CC28.svg)](https://lass.js.org)
[![license](https://img.shields.io/github/license/ladjs/auth.svg)](LICENSE)

> Auth for Lad


## Table of Contents

* [Install](#install)
* [Usage](#usage)
* [Options](#options)
* [Contributors](#contributors)
* [License](#license)


## Install

[npm][]:

```sh
npm install @ladjs/auth
```

[yarn][]:

```sh
yarn add @ladjs/auth
```


## Usage

```js
const Auth = require('@ladjs/auth');
const koa = require('koa');
const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');

const User = new mongoose.Schema();
User.plugin(passportLocalMongoose, {
  // ...
});
const Users = mongoose.model('User', UserSchema);

const auth = new Auth(Users, {
  // ...
});

const app = new Koa();
app.use(auth.passport.initialize());
app.use(auth.passport.session());
```


## Options

See [index.js](index.js) for configuration defaults and environment flags.


## Contributors

| Name           | Website                    |
| -------------- | -------------------------- |
| **Nick Baugh** | <http://niftylettuce.com/> |


## License

[MIT](LICENSE) © [Nick Baugh](http://niftylettuce.com/)


## 

[npm]: https://www.npmjs.com/

[yarn]: https://yarnpkg.com/
