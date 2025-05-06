const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('./db');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Signup route
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const stmt = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)');
  stmt.run(email, hashed, function(err) {
    if (err) return res.status(400).send('User already exists.');
    res.send('User registered.');
  });
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user) return res.status(404).send('User not found.');
    const match = await bcrypt.compare(password, user.password);
    if (match) return res.send('Login successful.');
    res.status(401).send('Invalid credentials.');
  });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
