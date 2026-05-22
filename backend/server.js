// server.js - Simple Express backend for CGPA Calculator
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs-extra');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

app.use(cors());
app.use(express.json());

// Serve static front‑end files
app.use(express.static(path.join(__dirname, '..')));

// Helper to read/write JSON files
const USERS_FILE = path.join(__dirname, 'users.json');
const STUDENTS_FILE = path.join(__dirname, 'students.json');

async function loadUsers() {
  try { return await fs.readJson(USERS_FILE); } catch (_) { return []; }
}
async function saveUsers(users) { await fs.writeJson(USERS_FILE, users, { spaces: 2 }); }
async function loadStudents() { try { return await fs.readJson(STUDENTS_FILE); } catch (_) { return []; }
}
async function saveStudents(students) { await fs.writeJson(STUDENTS_FILE, students, { spaces: 2 }); }

// Initialise default admin if no users exist
(async () => {
  const users = await loadUsers();
  if (users.length === 0) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash('admin123', salt);
    await saveUsers([{ id: 1, username: 'admin', passwordHash: hash }]);
    console.log('Created default admin user (admin / admin123)');
  }
})();

// Middleware to protect routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// ---------- Auth Endpoints ----------
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ msg: 'Missing fields' });
  const users = await loadUsers();
  if (users.find(u => u.username === username)) {
    return res.status(409).json({ msg: 'User already exists' });
  }
  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash(password, salt);
  const newUser = { id: Date.now(), username, passwordHash };
  users.push(newUser);
  await saveUsers(users);
  res.json({ msg: 'User registered' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const users = await loadUsers();
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ msg: 'Invalid credentials' });
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ msg: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ token });
});

// ---------- Student CGPA Endpoints (protected) ----------
app.get('/api/students', authenticateToken, async (req, res) => {
  const students = await loadStudents();
  res.json(students);
});

app.post('/api/students', authenticateToken, async (req, res) => {
  const newRecord = { id: Date.now(), ...req.body };
  const students = await loadStudents();
  students.push(newRecord);
  await saveStudents(students);
  res.json(newRecord);
});

app.put('/api/students/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const students = await loadStudents();
  const idx = students.findIndex(s => s.id == id);
  if (idx === -1) return res.status(404).json({ msg: 'Not found' });
  students[idx] = { ...students[idx], ...req.body };
  await saveStudents(students);
  res.json(students[idx]);
});

app.delete('/api/students/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  let students = await loadStudents();
  const initialLen = students.length;
  students = students.filter(s => s.id != id);
  if (students.length === initialLen) return res.status(404).json({ msg: 'Not found' });
  await saveStudents(students);
  res.json({ msg: 'Deleted' });
});

app.listen(PORT, () => console.log(`Backend listening on http://localhost:${PORT}`));
