// server.js
require('dotenv').config();            // โหลดค่าใน .env
const express     = require('express');
const mongoose    = require('mongoose');
const jwt         = require('jsonwebtoken');
const bcrypt      = require('bcrypt');
const bodyParser  = require('body-parser');
const cors        = require('cors');

const app         = express();
const PORT        = process.env.PORT || 3000;
const SECRET_KEY  = process.env.SECRET_KEY || 'my-secret-key';

// ─── เชื่อมต่อ MongoDB ───────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected!'))
  .catch(err => console.error('❌ Connection error:', err));

// ─── มิดเดิลแวร์ ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));  // เสิร์ฟไฟล์ในโฟลเดอร์ public

// ─── สร้าง Schemas & Models ──────────────────────────────────────────────────
const HistorySchema = new mongoose.Schema({
  code:  String,
  date:  { type: Date, default: Date.now }
}, { _id: false });

const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  points:   { type: Number, default: 0 },
  history:  [HistorySchema],
  role:     { type: String, enum: ['user','admin'], default: 'user' }
});
const CodeSchema = new mongoose.Schema({
  code:   { type: String, unique: true, required: true },
  points: { type: Number, required: true }
});
const RewardSchema = new mongoose.Schema({
  name:     { type: String, unique: true, required: true },
  points:   { type: Number, required: true },
  quantity: { type: Number, required: true }
});

const User   = mongoose.model('User', UserSchema);
const Code   = mongoose.model('Code', CodeSchema);
const Reward = mongoose.model('Reward', RewardSchema);

// ─── ฟังก์ชันช่วยตรวจ JWT ─────────────────────────────────────────────────
function authorize(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'Missing token' });
  try {
    req.user = jwt.verify(token, SECRET_KEY);
    next();
  } catch {
    res.status(403).json({ msg: 'Invalid or expired token' });
  }
}

// ─── ROUTES ────────────────────────────────────────────────────────────────────

// 1) สมัครสมาชิก
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ msg: 'Username and password required' });

    if (await User.exists({ username }))
      return res.status(400).json({ msg: 'User already exists' });

    const hash = await bcrypt.hash(password, 10);
    await User.create({ username, password: hash });
    res.json({ msg: 'Registration successful' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// 2) เข้าสู่ระบบ
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ msg: 'Invalid credentials' });

    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '2h' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// 3) ดูข้อมูลผู้ใช้ (Profile)
app.get('/api/me', authorize, async (req, res) => {
  const user = await User.findOne({ username: req.user.username })
    .select('-password -__v');
  if (!user) return res.status(404).json({ msg: 'User not found' });
  res.json(user);
});

// 4) เช็คโค้ดแลกแต้ม (เพิ่มแต้ม)
app.post('/api/check-code', authorize, async (req, res) => {
  try {
    const { code } = req.body;
    const found = await Code.findOne({ code });
    if (!found) return res.status(404).json({ msg: 'Invalid code' });

    const user = await User.findOne({ username: req.user.username });
    user.points += found.points;
    user.history.push({ code, date: new Date() });
    await user.save();
    res.json({ msg: 'Success', reward: found.points, points: user.points });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// 5) ดูรางวัลทั้งหมด
app.get('/api/rewards', async (req, res) => {
  const list = await Reward.find().select('-__v');
  res.json(list);
});

// 6) เพิ่มแต้มให้ผู้ใช้ (Admin)
app.post('/api/admin/add-points', authorize, async (req, res) => {
  try {
    const admin = await User.findOne({ username: req.user.username });
    if (admin.role !== 'admin')
      return res.status(403).json({ msg: 'Forbidden' });

    const { username, points } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ msg: 'User not found' });

    user.points += Number(points);
    await user.save();
    res.json({ msg: `Added ${points} points to ${username}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// 7) แลกรางวัล
app.post('/api/redeem', authorize, async (req, res) => {
  try {
    const { name } = req.body;
    const reward = await Reward.findOne({ name });
    if (!reward) return res.status(404).json({ msg: 'Reward not found' });

    const user = await User.findOne({ username: req.user.username });
    if (user.points < reward.points)
      return res.status(400).json({ msg: 'Insufficient points' });
    if (reward.quantity <= 0)
      return res.status(400).json({ msg: 'Out of stock' });

    user.points -= reward.points;
    reward.quantity -= 1;
    user.history.push({ code: name, date: new Date() });
    await Promise.all([ user.save(), reward.save() ]);
    res.json({ msg: 'Redeemed successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// 8) อัพเดตจำนวนสินค้า (Admin)
app.post('/api/update-quantity', authorize, async (req, res) => {
  try {
    const admin = await User.findOne({ username: req.user.username });
    if (admin.role !== 'admin')
      return res.status(403).json({ msg: 'Forbidden' });

    const { name, quantity } = req.body;
    const reward = await Reward.findOne({ name });
    if (!reward) return res.status(404).json({ msg: 'Reward not found' });

    reward.quantity = Number(quantity);
    await reward.save();
    res.json({ msg: 'Quantity updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// 9) ดูรายชื่อผู้ใช้ทั้งหมด (Admin)
app.get('/api/all-users', authorize, async (req, res) => {
  const admin = await User.findOne({ username: req.user.username });
  if (admin.role !== 'admin')
    return res.status(403).json({ msg: 'Forbidden' });

  const list = await User.find().select('username points role');
  res.json(list);
});

// 10) รีเซ็ตรหัสผ่าน
app.post('/api/reset-password', async (req, res) => {
  try {
    const { username, newPassword } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ msg: 'User not found' });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ msg: 'Password reset successful' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// ─── สตาร์ทเซิร์ฟเวอร์ ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
