// server.js
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const SECRET = 'super_secret_key'; // change this later

app.use(cors({ origin: '*', credentials: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Setup PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://user_db_50z6_user:PVqWjbLdDi3MdX0ajWHV1cOvzvM9A45z@dpg-d4199tp8ocjs73cjgcug-a/user_db_50z6',
  ssl: { rejectUnauthorized: false } // Required by Render
});

// Test connection
pool.connect()
  .then(() => console.log('Connected to PostgreSQL database.'))
  .catch(err => console.error('Connection error', err.stack));

// Create user table if not exists
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    isAdmin BOOLEAN DEFAULT false,
    username TEXT UNIQUE,
    password TEXT,
    api_calls INTEGER DEFAULT 0
  );
`).then(() => console.log('Users table ready'))
  .catch(err => console.error(err));

// Register
app.post('/register', async (req, res) => {
  const { username, password, isAdmin } = req.body;

  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO users (username, password, api_calls, isAdmin)
       VALUES ($1, $2, 0, $3)`,
      [username, hashed, isAdmin ? true : false]
    );
    res.json({ message: 'User created successfully' });
  } catch (err) {
    if (err.message.includes('duplicate key')) {
      return res.status(400).json({ message: 'Username already exists' });
    }
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ message: 'Invalid username or password' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Invalid username or password' });

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '1h' });

    res.json({
      token,
      username: user.username,
      isAdmin: user.isadmin
    });
  } catch (err) {
    res.status(500).json({ message: 'Database error' });
  }
});

app.post('/user/resume', authenticateToken, async (req, res) => {
    const username = req.user.username; // from token
    const { resume } = req.body;
    // Save resume to DB for this user
});

// Middleware
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

// Verify token route
app.get('/verify-token', authenticate, (req, res) => {
  res.json({ username: req.user.username });
});

// Example API route
app.get('/call-ai', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT api_calls FROM users WHERE id = $1', [req.user.id]);
    const calls = result.rows[0]?.api_calls ?? 0;

    if (calls >= 20) {
      return res.json({ message: 'You’ve used all 20 free API calls. Continuing in demo mode.' });
    }

    await pool.query('UPDATE users SET api_calls = api_calls + 1 WHERE id = $1', [req.user.id]);
    res.json({ message: `AI call successful! (${calls + 1}/20 used)` });
  } catch (err) {
    res.status(500).json({ message: 'Database error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
