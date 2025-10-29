// server.js
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const SECRET = 'super_secret_key'; // change this to something secure later

app.use(cors({ origin: '*', credentials: true })); // adjust origin if needed
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Setup SQLite
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) console.error(err.message);
  else console.log('Connected to SQLite database.');
});

// Create user table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    isAdmin BOOLEAN DEFAULT 0,
    username TEXT UNIQUE,
    password TEXT,
    api_calls INTEGER DEFAULT 0
  )
`);

// Register
app.post('/register', async (req, res) => {
  const { username, password, isAdmin } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (username, password, api_calls, isAdmin) VALUES (?, ?, 0, ?)`,
    [username, hashed, isAdmin ? 1 : 0],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ message: 'Username already exists' });
        }
        return res.status(500).json({ message: 'Database error' });
      }
      res.json({ message: 'User created successfully' });
    }
  );
});


// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
    if (err || !row) return res.status(400).json({ message: 'Invalid username or password' });

    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.status(400).json({ message: 'Invalid username or password' });

    const token = jwt.sign({ id: row.id, username: row.username }, SECRET, { expiresIn: '1h' });

    // Convert isAdmin to boolean
    const isAdmin = row.isAdmin == 1; // true if 1, false if 0

    res.json({
      token,
      username: row.username,
      isAdmin
    });
  });
});


// middleware
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Missing token' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// route
app.get('/verify-token', authenticate, (req, res) => {
  res.json({ username: req.user.username });
});


// Example API route (simulate calling your AI model)
app.get('/call-ai', authenticate, (req, res) => {
  db.get(`SELECT api_calls FROM users WHERE id = ?`, [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ message: 'Database error' });

    const calls = row?.api_calls ?? 0;
    if (calls >= 20) {
      return res.json({ message: 'You’ve used all 20 free API calls. Continuing in demo mode.' });
    }

    db.run(`UPDATE users SET api_calls = api_calls + 1 WHERE id = ?`, [req.user.id]);
    res.json({ message: `AI call successful! (${calls + 1}/20 used)` });
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
