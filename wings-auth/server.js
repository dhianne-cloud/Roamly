const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const TOKENS_FILE = path.join(DATA_DIR, 'tokens.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const readJSON = (file, def) => {
  try {
    if (!fs.existsSync(file)) return def;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch { return def; }
};
const writeJSON = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'wings-for-growth-2024-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, message: 'Email and password are required.' });

  const users = readJSON(USERS_FILE, []);
  const user = users.find(u => u.email === email.toLowerCase().trim());

  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ success: false, message: 'Invalid email or password.' });

  req.session.userId = user.id;
  req.session.email = user.email;
  res.json({ success: true, message: 'Logged in successfully.', user: { email: user.email, name: user.name } });
});

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ success: false, message: 'All fields are required.' });
  if (password.length < 8)
    return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });

  const users = readJSON(USERS_FILE, []);
  if (users.find(u => u.email === email.toLowerCase().trim()))
    return res.status(409).json({ success: false, message: 'An account with this email already exists.' });

  const newUser = {
    id: crypto.randomUUID(),
    name: name.trim(),
    email: email.toLowerCase().trim(),
    password: await bcrypt.hash(password, 12),
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  writeJSON(USERS_FILE, users);

  req.session.userId = newUser.id;
  req.session.email = newUser.email;
  res.status(201).json({ success: true, message: 'Account created successfully.', user: { email: newUser.email, name: newUser.name } });
});

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email)
    return res.status(400).json({ success: false, message: 'Email is required.' });

  const emailLower = email.toLowerCase().trim();
  const users = readJSON(USERS_FILE, []);
  const user = users.find(u => u.email === emailLower);

  const token = crypto.randomBytes(32).toString('hex');
  const tokens = readJSON(TOKENS_FILE, {});
  const now = Date.now();

  // Clean up expired tokens
  Object.keys(tokens).forEach(t => { if (tokens[t].expires < now) delete tokens[t]; });

  if (user) {
    tokens[token] = { email: emailLower, expires: now + 15 * 60 * 1000 };
    writeJSON(TOKENS_FILE, tokens);
  }

  res.json({
    success: true,
    message: 'If an account exists, a reset link has been sent.',
    // NOTE: In production never return the token here — email it instead.
    // Returned here only for demo purposes.
    resetToken: user ? token : null
  });
});

// GET /api/auth/validate-token/:token
app.get('/api/auth/validate-token/:token', (req, res) => {
  const tokens = readJSON(TOKENS_FILE, {});
  const data = tokens[req.params.token];
  if (!data || data.expires < Date.now())
    return res.status(400).json({ success: false, message: 'Invalid or expired token.' });
  res.json({ success: true, email: data.email });
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password)
    return res.status(400).json({ success: false, message: 'Token and password are required.' });
  if (password.length < 8)
    return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });

  const tokens = readJSON(TOKENS_FILE, {});
  const data = tokens[token];
  if (!data || data.expires < Date.now())
    return res.status(400).json({ success: false, message: 'Invalid or expired reset token.' });

  const users = readJSON(USERS_FILE, []);
  const idx = users.findIndex(u => u.email === data.email);
  if (idx === -1)
    return res.status(404).json({ success: false, message: 'User not found.' });

  users[idx].password = await bcrypt.hash(password, 12);
  writeJSON(USERS_FILE, users);
  delete tokens[token];
  writeJSON(TOKENS_FILE, tokens);

  res.json({ success: true, message: 'Password changed successfully.' });
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// GET /api/auth/me
app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId)
    return res.status(401).json({ success: false });
  res.json({ success: true, email: req.session.email });
});

// Seed a demo user on first start
async function seedDemo() {
  const users = readJSON(USERS_FILE, []);
  if (users.length === 0) {
    users.push({
      id: crypto.randomUUID(),
      name: 'Demo Mentor',
      email: 'mentor@example.com',
      password: await bcrypt.hash('Mentor@123', 12),
      createdAt: new Date().toISOString()
    });
    writeJSON(USERS_FILE, users);
    console.log('Demo account seeded:');
    console.log('  Email   : mentor@example.com');
    console.log('  Password: Mentor@123\n');
  }
}

seedDemo().then(() => {
  app.listen(PORT, () => {
    console.log(`Wings for Growth server running at http://localhost:${PORT}`);
  });
});
