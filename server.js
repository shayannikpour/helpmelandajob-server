// server.js
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');


const app = express();
const PORT = 3000;
const SECRET = process.env.SECRET;
// Fixed application-wide API quota (do not store per-user quota in the database)
const API_QUOTA = 20;

app.use(cors({ origin: '*', credentials: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.json());

// Setup PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Required by Render
});

// Test connection
pool.connect()
  .then(() => console.log('Connected to PostgreSQL database.'))
  .catch(err => console.error('Connection error', err.stack));

// Create users table if not exists
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    isadmin BOOLEAN DEFAULT false,
    username TEXT UNIQUE,
    password TEXT,
    api_calls INTEGER DEFAULT 0
  );
`).then(() => {
  console.log('Users table ready');

  // Add resume column if it doesn't exist
  return pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS resume TEXT;
  `);
}).then(() => {
  // Add skills column if it doesn't exist
  return pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS skills TEXT[];
  `);
}).then(() => {
  console.log('Resume and skills columns ready');
}).catch(err => console.error(err));

pool.query(`
  CREATE TABLE IF NOT EXISTS endpoints (
    id SERIAL PRIMARY KEY,
    method TEXT,
    endpoint TEXT,
    requests INTEGER DEFAULT 0
  );
   `).then(() => {
    console.log('Endpoints table ready');
}).catch(err => console.error('Endpoints table error', err));

app.delete('/admin/users/:id', authenticate, async (req, res) => {
  console.log(req.user.isAdmin);
  if (!req.user.isAdmin) {
    return res.status(403).json({ message: 'Admin access required' });
  }
  const userId = req.params.id;
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    res.json({ message: 'User deleted successfully' });
  }
  catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.patch('/admin/users/:id/isAdmin', authenticate, async (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ message: 'Admin access required' });
  }
  const userId = req.params.id;
  const { isAdmin } = req.body;
  try {
    await pool.query('UPDATE users SET isAdmin = $1 WHERE id = $2', [isAdmin, userId]);
    res.json({ message: 'User admin status updated successfully' });
  }
  catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

async function incrementEndpoint(method, endpoint) {
  try {
    await pool.query(
      `
      UPDATE endpoints
      SET requests = requests + 1
      WHERE method = $1 AND endpoint = $2
      `,
      [method, endpoint]
    );
  } catch (err) {
    console.error("Failed to update endpoint usage:", err);
  }
}




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

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        isAdmin: user.isadmin   
      },
      SECRET,
      { expiresIn: '1h' }
    );


    res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });

    res.json({
      token,
      username: user.username,
      isAdmin: user.isadmin
    });
  } catch (err) {
    res.status(500).json({ message: 'Database error' });
  }
});

app.post('/user/resume', authenticate, async (req, res) => {
  const username = req.user.username;
  const { resume } = req.body;

  if (!resume) {
    return res.status(400).json({ message: 'Resume text is required' });
  }

  try {
    // enforce quota and increment (saving resume counts as an action)
    const selectRes = await pool.query('SELECT id, api_calls FROM users WHERE username = $1', [username]);
    const userId = selectRes.rows[0]?.id;
    if (!userId) return res.status(404).json({ message: 'User not found' });

    try {
      await checkAndIncrement(userId);
    } catch (err) {
      if (err.code === 'QUOTA_EXCEEDED') {
        return res.status(429).json({ message: `API quota exceeded (${err.count}/${API_QUOTA})` });
      }
      throw err;
    }

    await pool.query(
      'UPDATE users SET resume = $1 WHERE username = $2',
      [resume, username]
    );
    res.json({ message: 'Resume saved successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.get('/user/resume', authenticate, async (req, res) => {
  const username = req.user.username;

  try {
    const result = await pool.query('SELECT resume FROM users WHERE username = $1', [username]);
    const resume = result.rows[0]?.resume || '';
    res.json({ resume });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.get('/user/api_calls', authenticate, async (req, res) => {
  const username = req.user.username;

  try {
    const result = await pool.query('SELECT api_calls FROM users WHERE username = $1', [username]);
    const api_calls = Number(result.rows[0]?.api_calls ?? 0);
    res.json({ api_calls });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.post('/user/skills', authenticate, async (req, res) => {
  const username = req.user.username;
  const { skill } = req.body;

  if (!skill || typeof skill !== 'string' || !skill.trim()) {
    return res.status(400).json({ message: 'Skill is required' });
  }

  const trimmed = skill.trim();
  try {
    // Load current skills to dedupe
    const r = await pool.query('SELECT skills, id FROM users WHERE username = $1', [username]);
    const row = r.rows[0] || {};
    const userId = row.id;
    const skills = Array.isArray(row.skills) ? row.skills : [];

    const exists = skills.some(s => String(s).toLowerCase() === trimmed.toLowerCase());
    if (exists) {
      return res.json({ message: 'Skill already exists' });
    }

    // enforce quota and increment
    try {
      await checkAndIncrement(userId);
    } catch (err) {
      if (err.code === 'QUOTA_EXCEEDED') {
        return res.status(429).json({ message: `API quota exceeded (${err.count}/${API_QUOTA})` });
      }
      throw err;
    }

    // Append the new skill
    await pool.query(
      `UPDATE users
       SET skills = COALESCE(skills, ARRAY[]::text[]) || ARRAY[$1]
       WHERE username = $2`,
      [trimmed, username]
    );
    res.json({ message: 'Skill added successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
});

app.get('/user/skills', authenticate, async (req, res) => {
  const username = req.user.username;

  try {
    const result = await pool.query('SELECT skills FROM users WHERE username = $1', [username]);
    const skills = result.rows[0]?.skills || [];
    res.json({ skills });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Database error' });
  }
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

// Helper to increment a user's api_calls counter and return the updated count
async function incrementApiCalls(userId) {
  try {
    const result = await pool.query(
      'UPDATE users SET api_calls = COALESCE(api_calls, 0) + 1 WHERE id = $1 RETURNING api_calls',
      [userId]
    );
    return result.rows[0]?.api_calls ?? null;
  } catch (err) {
    console.error('Failed to increment api_calls for user', userId, err);
    throw err;
  }
}

// Check quota then increment; throws an error with code 'QUOTA_EXCEEDED' if over limit
async function checkAndIncrement(userId) {
  try {
    const cur = await pool.query('SELECT api_calls FROM users WHERE id = $1', [userId]);
    const calls = cur.rows[0]?.api_calls ?? 0;
    if (API_QUOTA >= 0 && calls >= API_QUOTA) {
      const err = new Error('API quota exceeded');
      err.code = 'QUOTA_EXCEEDED';
      err.count = calls;
      throw err;
    }
    return await incrementApiCalls(userId);
  } catch (err) {
    throw err;
  }
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

    if (API_QUOTA >= 0 && calls >= API_QUOTA) {
      return res.status(429).json({ message: `API quota exceeded (${calls}/${API_QUOTA})` });
    }

    const newCount = await incrementApiCalls(req.user.id);
    res.json({ message: `AI call successful! (${newCount}/${API_QUOTA} used)` });
  } catch (err) {
    res.status(500).json({ message: 'Database error' });
  }
});

// AI resume improvement proxy endpoint
app.post('/ai/resume/improve', authenticate, async (req, res) => {
  const { resume } = req.body;
  if (!resume) return res.status(400).json({ message: 'Resume text is required' });

  try {
    // enforce quota and increment api_calls
    try {
      await checkAndIncrement(req.user.id);
    } catch (err) {
      if (err.code === 'QUOTA_EXCEEDED') {
        return res.status(429).json({ message: `API quota exceeded (${err.count}/${API_QUOTA})` });
      }
      throw err;
    }

    // Call external AI service
    if (typeof fetch !== 'function') {
      return res.status(500).json({ message: 'Server fetch is not available. Install node-fetch or upgrade Node.' });
    }

    const aiRes = await fetch('https://teamv5.duckdns.org/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages: [
          { role: 'system', content: 'You are an expert resume enhancer. Suggest point form improvements for the following resume to make it more appealing to employers.' },
          { role: 'user', content: `This is the resume:\n\n${resume}` }
        ]
      })
    });

    const aiJson = await aiRes.json().catch(() => ({}));

    // Return AI response to the client
    res.status(aiRes.ok ? 200 : 502).json({ ai: aiJson });
  } catch (err) {
    console.error('AI proxy error:', err);
    res.status(500).json({ message: 'AI proxy error', error: err.message });
  }
});

// LeetCode AI Endpoint
app.post('/ai/leetcode', authenticate, async (req, res) => {

  incrementEndpoint("POST", "/ai/leetcode");

  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: "Prompt is required" });

  try {
    await checkAndIncrement(req.user.id);
  } catch (err) {
    if (err.code === 'QUOTA_EXCEEDED') {
      return res.status(429).json({ message: `API quota exceeded (${err.count}/${API_QUOTA})` });
    }
    throw err;
  }

  try {
    const aiRes = await fetch("https://teamv5.duckdns.org/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        messages: [
          { role: "system", content: "You output ONLY valid JSON." },
          { role: "user", content: prompt }
        ],
        stop: ["```", "Here is", "\n\n"]
      })
    });

    const aiJson = await aiRes.json();
    res.status(aiRes.ok ? 200 : 502).json(aiJson);

  } catch (err) {
    console.error("AI LeetCode error:", err);
    res.status(500).json({ error: "AI error", detail: err.message });
  }
});

app.post('/jobs/search_user', authenticate, async (req, res) => {
  try {
    const response = await fetch("https://teamv5.duckdns.org/jobs/search_user", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req.body)
    });

    const data = await response.json();
    res.status(response.ok ? 200 : 500).json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal proxy error" });
  }
});


app.get('/admin/users', authenticate, async (req, res) => {
  try {
    const adminCheck = await pool.query(
      'SELECT isAdmin FROM users WHERE id = $1',
      [req.user.id]
    );

    if (!adminCheck.rows[0]?.isadmin) {
      return res.status(403).json({ message: "Admin access required" });
    }

    const result = await pool.query(`
      SELECT id, username, api_calls, isadmin
      FROM users
      ORDER BY username ASC
    `);

    res.json({ users: result.rows });

  } catch (err) {
    console.error("ADMIN /admin/users ERROR:", err);
    res.status(500).json({ message: "Database error" });
  }
});


// app.use(async (req, res, next) => {
//   try {
//     const method = req.method;
//     const path = req.path; // Raw path

//     // Fetch all endpoint patterns once
//     const result = await pool.query(`
//       SELECT id, method, endpoint FROM endpoints
//     `);

//     let matchedId = null;

//     for (const ep of result.rows) {
//       if (ep.method !== method) continue;

      
//       const pattern = ep.endpoint.replace(/:[^/]+/g, "[^/]+");
//       const regex = new RegExp(`^${pattern}$`);

//       if (regex.test(path)) {
//         matchedId = ep.id;
//         break;
//       }
//     }

//     if (matchedId) {
//       await pool.query(
//         `UPDATE endpoints SET requests = requests + 1 WHERE id = $1`,
//         [matchedId]
//       );
//     }

//   } catch (err) {
//     console.error("Endpoint tracking error:", err);
//   }

//   next();
// });





app.get('/admin/endpoints', authenticate, async (req, res) => {
  try {
    
    const adminCheck = await pool.query(
      'SELECT isAdmin FROM users WHERE id = $1',
      [req.user.id]
    );

    if (!adminCheck.rows[0]?.isadmin) {
      return res.status(403).json({ message: "Admin access required" });
    }

    
    const result = await pool.query(`
      SELECT id, method, endpoint, requests
      FROM endpoints
      ORDER BY id ASC
    `);

    res.json({ endpoints: result.rows });

  } catch (err) {
    console.error("ADMIN /admin/endpoints ERROR:", err);
    res.status(500).json({ message: "Database error" });
  }
});


app.delete('/user/skills', authenticate, async (req, res) => {
  const username = req.user.username;
  const { skill } = req.body;

  if (!skill) {
    return res.status(400).json({ message: 'Skill is required' });
  }

  try {
    const result = await pool.query(
      `UPDATE users
       SET skills = array_remove(skills, $1)
       WHERE username = $2
       RETURNING skills`,
      [skill, username]
    );

    return res.json({
      message: "Skill deleted successfully",
      skills: result.rows[0].skills || []
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Database error" });
  }
});


app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
