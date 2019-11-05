'use strict';

const express = require('express');
const bcryptjs = require('bcryptjs');
const auth = require('basic-auth');
const { check, validationResult } = require('express-validator');

const validators = [
  check('name')
    .exists()
    .withMessage('Please provide a value for "name"'),
  check('username')
    .exists()
    .withMessage('Please provide a value for "username"'),
  check('password')
    .exists()
    .withMessage('Please provide a value for "password"'),
];

const authenticateUser = (req, res, next) => {
  let message = null;

  const credentials = auth(req);

  // If the user's credentials are available...
  if (credentials) {
    const user = users.find(u => u.username === credentials.name);

    // If a user was successfully retrieved from the data store...
    if (user) {
      const authenticated = bcryptjs
        .compareSync(credentials.pass, user.password);

      // If the passwords match...
      if (authenticated) {
        console.log(`Authentication successful for username: ${user.username}`);

        // Then store the retrieved user object on the request object
        // so any middleware functions that follow this middleware function
        // will have access to the user's information.
        req.currentUser = user;
      } else {
        message = `Authentication failure for username: ${user.username}`;
      }
    } else {
      message = `User not found for username: ${credentials.name}`;
    }
  } else {
    message = 'Auth header not found';
  }

  // If user authentication failed...
  if (message) {
    console.warn(message);
    res.status(401).json({ message: 'Access Denied' });
  } else {
    next();
  }
};

const router = express.Router();
const users = [];

// Route that returns the current authenticated user.
router.get('/users', authenticateUser, (req, res) => {
  const user = req.currentUser;

  res.json({
    name: user.name,
    username: user.username,
  });
});

// Route that creates a new user.
router.post('/users', validators, (req, res) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => error.msg);

    return res.status(400).json({ errors: errorMessages });
  }

  const user = req.body;

  user.password = bcryptjs.hashSync(user.password);
  users.push(user);
  res.status(201).end();
});

module.exports = router;
