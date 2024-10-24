const express = require('express');
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model');
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require('./auth-middleware');

const router = express.Router();

router.post('/register', checkUsernameFree, checkPasswordLength, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 8);
    const newUser = await Users.add({ username, password: hash });
    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
});

router.post('/login', checkUsernameExists, async (req, res, next) => {
  try {
    const { password } = req.body;
    if (bcrypt.compareSync(password, req.user.password)) {
      req.session.user = req.user;
      res.json({ message: `Welcome ${req.user.username}!` });
    } else {
      next({ status: 401, message: "Invalid credentials" });
    }
  } catch (err) {
    next(err);
  }
});

router.get('/logout', (req, res, next) => {
  if (req.session.user) {
    req.session.destroy(err => {
      if (err) {
        next(err);
      } else {
        res.json({ message: "logged out" });
      }
    });
  } else {
    res.json({ message: "no session" });
  }
});

module.exports = router;
