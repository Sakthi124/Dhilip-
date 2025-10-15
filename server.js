const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'supersecretkey';

app.use(cors());
app.use(bodyParser.json());

// In-memory "database"
const users = [
  { id: 1, username: 'admin', passwordHash: '', role: 'admin' }
];
const orders = [
  { id: 1, userId: 1, amount: 250, date: '2025-10-01' },
  { id: 2, userId: 1, amount: 400, date: '2025-10-02' },
  { id: 3, userId: 1, amount: 320, date: '2025-10-03' },
  { id: 4, userId: 1, amount: 520, date: '2025-10-04' },
];
const stats = {
  totalUsers: users.length,
  totalOrders: orders.length,
  totalRevenue: orders.reduce((sum, o) => sum + o.amount, 0)
};

// Hash admin password once
(async () => {
  users[0].passwordHash = await bcrypt.hash('adminpassword', 10);
})();

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Login Route
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(400).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Dashboard Route
app.get('/api/dashboard', authenticateToken, (req, res) => {
  const recentOrders = orders.slice(-5);
  res.json({
    stats,
    recentOrders
  });
});

// Users Route
app.get('/api/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  res.json(users.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role
  })));
});

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
