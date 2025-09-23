const express = require('express');
const router = express.Router();
const { signForUser } = require('../middleware/jwt');

// Hard-coded users (valid for A1)
const USERS = [
  { username: 'user', password: 'user', role: 'user' },
  { username: 'admin', password: 'admin', role: 'admin' }
];

router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const found = USERS.find(u => u.username === username && u.password === password);
  if (!found) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signForUser(found);
  res.json({ authToken: token, user: { username: found.username, role: found.role } });
});

module.exports = router;