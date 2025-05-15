// auth/authRoutes.js
const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'changeme';

const USERS = {
  camren: { password: 'adminpass', role: 'admin' },
  coty: { password: 'techpass', role: 'technician' },
};

router.post('/login', (req, res) => {
  const { username, password } = req.body;

  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

module.exports = router;
