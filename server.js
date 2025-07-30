const express = require('express');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

const SECRET = 'my-secret-key';

let users = JSON.parse(fs.readFileSync('./data/users.json', 'utf-8'));
let codes = JSON.parse(fs.readFileSync('./data/codes.json', 'utf-8'));
let rewards = JSON.parse(fs.readFileSync('./data/rewards.json', 'utf-8'));

// สมัคร
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (users[username]) return res.status(400).json({ msg: 'มีผู้ใช้นี้แล้ว' });

  const hashed = await bcrypt.hash(password, 10);
  users[username] = { password: hashed, points: 0, history: [], role: "user" };

  fs.writeFileSync('./data/users.json', JSON.stringify(users, null, 2));
  res.json({ msg: 'สมัครเรียบร้อย' });
});

// ล็อกอิน
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ msg: 'ชื่อผู้ใช้หรือรหัสผ่านผิด' });

  const token = jwt.sign({ username }, SECRET, { expiresIn: '2h' });
  res.json({ token });
});

// เช็ครหัสสินค้า
app.post('/api/check-code', (req, res) => {
  const auth = req.headers.authorization;
  const token = auth && auth.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'no token' });

  try {
    const decoded = jwt.verify(token, SECRET);
    const reward = codes[req.body.code];
    if (!reward) return res.status(404).json({ msg: 'โค้ดไม่ถูกต้อง' });

    const user = users[decoded.username];
    user.points += reward.points;
    user.history.push({ code: req.body.code, date: new Date().toISOString() });
    fs.writeFileSync('./data/users.json', JSON.stringify(users, null, 2));
    res.json({ msg: 'สำเร็จ', reward, points: user.points });
  } catch {
    res.status(403).json({ msg: 'token ไม่ถูกต้อง' });
  }
});

// me
app.get('/api/me', (req, res) => {
  const auth = req.headers.authorization;
  const token = auth && auth.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'no token' });

  try {
    const decoded = jwt.verify(token, SECRET);
    const user = users[decoded.username];
    res.json({ username: decoded.username, points: user.points, history: user.history, role: user.role });
  } catch {
    res.status(403).json({ msg: 'token ไม่ถูกต้อง' });
  }
});

// รายการของรางวัล
app.get('/api/rewards', (req, res) => {
  res.json(rewards);
});

// แอดมินเพิ่มแต้มให้ผู้ใช้
app.post('/api/admin/add-points', (req, res) => {
  const auth = req.headers.authorization;
  const token = auth && auth.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'no token' });

  try {
    const decoded = jwt.verify(token, SECRET);
    const currentUser = users[decoded.username];
    if (currentUser.role !== 'admin') return res.status(403).json({ msg: 'คุณไม่ใช่แอดมิน' });

    const { username, points } = req.body;
    if (!users[username]) return res.status(404).json({ msg: 'ไม่พบผู้ใช้' });

    users[username].points += points;
    fs.writeFileSync('./data/users.json', JSON.stringify(users, null, 2));
    res.json({ msg: `เพิ่มแต้มให้ ${username} เรียบร้อยแล้ว` });
  } catch {
    res.status(403).json({ msg: 'token ไม่ถูกต้อง' });
  }
});

// แลกของรางวัล
app.post('/api/redeem', (req, res) => {
  const auth = req.headers.authorization;
  const token = auth && auth.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'ไม่พบ token' });

  try {
    const decoded = jwt.verify(token, SECRET);
    const user = users[decoded.username];
    const { rewardName } = req.body;

    const reward = rewards[rewardName];
    if (!reward) return res.status(404).json({ msg: 'ไม่พบของรางวัล' });

    if (reward.quantity <= 0) {
      return res.status(400).json({ msg: 'ของรางวัลหมดแล้ว' });
    }

    if (user.points < reward.points) {
      return res.status(400).json({ msg: 'แต้มไม่เพียงพอ' });
    }

    user.points -= reward.points;
    reward.quantity -= 1;
    user.history = user.history || [];
    user.history.push({
      code: rewardName,
      date: new Date().toISOString()
    });

    fs.writeFileSync('./data/users.json', JSON.stringify(users, null, 2));
    fs.writeFileSync('./data/rewards.json', JSON.stringify(rewards, null, 2));

    res.json({ msg: 'แลกของรางวัลสำเร็จ!' });
  } catch {
    res.status(403).json({ msg: 'token ไม่ถูกต้อง' });
  }
});

// อัปเดตจำนวนของรางวัล (admin)
app.post('/api/update-quantity', (req, res) => {
  const { rewardName, quantity } = req.body;

  if (!rewards[rewardName]) {
    return res.status(404).json({ msg: 'ไม่พบของรางวัล' });
  }

  rewards[rewardName].quantity = quantity;

  fs.writeFileSync('./data/rewards.json', JSON.stringify(rewards, null, 2));
  res.json({ msg: 'อัปเดตจำนวนสำเร็จ' });
});

app.get('/api/all-users', (req, res) => {
  res.json(users);
});

// ลืมรหัสผ่าน (reset)
app.post('/api/reset-password', async (req, res) => {
  const { username, newPassword } = req.body;

  if (!users[username]) return res.status(404).json({ msg: 'ไม่พบผู้ใช้นี้' });

  const hashed = await bcrypt.hash(newPassword, 10);
  users[username].password = hashed;

  fs.writeFileSync('./data/users.json', JSON.stringify(users, null, 2));
  res.json({ msg: 'เปลี่ยนรหัสผ่านเรียบร้อยแล้ว' });
});


app.listen(3000, () => console.log('🚀 Server running on http://localhost:3000'));
