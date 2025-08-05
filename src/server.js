// src/server.js
require('dotenv').config();
const express    = require('express');
const mongoose   = require('mongoose');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcrypt');
const bodyParser = require('body-parser');
const cors       = require('cors');
const multer     = require('multer');
const path       = require('path');

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = process.env.SECRET_KEY;

// ─── MongoDB ─────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// ─── Middleware ─────────────────────────────────────────────────────────────
app.use(cors());
app.use(bodyParser.json());

// เสิร์ฟไฟล์ static จาก public (ชั้นบน src/)
app.use('/images', express.static(path.join(__dirname, '..', 'public', 'images')));
app.use(express.static(path.join(__dirname, '..', 'public')));

// ─── Schemas & Models ────────────────────────────────────────────────────────
const HistorySchema = new mongoose.Schema({ code: String, date: Date }, { _id: false });
const UserSchema    = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  points:   { type: Number, default: 0 },
  history:  [HistorySchema],
  role:     { type: String, enum: ['user','admin'], default: 'user' }
});
const CodeSchema   = new mongoose.Schema({ code: String, points: Number });
const RewardSchema = new mongoose.Schema({
  name:     { type: String, unique: true, required: true },
  points:   { type: Number, required: true },
  quantity: { type: Number, required: true },
  image:    { type: String, default: 'placeholder.png' }
});

const User   = mongoose.model('User', UserSchema);
const Code   = mongoose.model('Code', CodeSchema);
const Reward = mongoose.model('Reward', RewardSchema);

// ─── JWT Helper ─────────────────────────────────────────────────────────────
function authorize(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'Missing token' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(403).json({ msg: 'Invalid or expired token' });
  }
}

// ─── Multer Setup ────────────────────────────────────────────────────────────
const IMAGES_DIR = path.join(__dirname, '..', 'public', 'images');
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, IMAGES_DIR),
  filename:    (req, file, cb) => {
    const safe = Date.now() + '-' + file.originalname.replace(/\s+/g, '_');
    cb(null, safe);
  }
});
const upload = multer({ storage });

// ─── Admin Checker ───────────────────────────────────────────────────────────
async function isAdmin(req, res, next) {
  const u = await User.findOne({ username: req.user.username });
  if (!u || u.role !== 'admin') return res.status(403).json({ msg: 'Forbidden' });
  next();
}

// ─── ROUTES ─────────────────────────────────────────────────────────────────

// 1) Register
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

// รีเซ็ตรหัสผ่าน
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


// 2) Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const u = await User.findOne({ username });
    if (!u || !(await bcrypt.compare(password, u.password)))
      return res.status(401).json({ msg: 'Invalid credentials' });
    const token = jwt.sign({ username }, SECRET, { expiresIn: '2h' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// 3) Profile
app.get('/api/me', authorize, async (req, res) => {
  const u = await User.findOne({ username: req.user.username }).select('-password -__v');
  if (!u) return res.status(404).json({ msg: 'User not found' });
  res.json(u);
});

// 4) Check Code (add points)
app.post('/api/check-code', authorize, async (req, res) => {
  try {
    const { code } = req.body;
    const c = await Code.findOne({ code });
    if (!c) return res.status(404).json({ msg: 'Invalid code' });
    const u = await User.findOne({ username: req.user.username });
    u.points += c.points;
    u.history.push({ code, date: new Date() });
    await u.save();
    res.json({ msg: 'Success', reward: c.points, points: u.points });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// 5) List Rewards
app.get('/api/rewards', async (req, res) => {
  const list = await Reward.find().select('-__v');
  res.json(list);
});

// 6) Add Points (admin)
app.post('/api/admin/add-points', authorize, isAdmin, async (req, res) => {
  try {
    const { username, points } = req.body;
    const u = await User.findOne({ username });
    if (!u) return res.status(404).json({ msg: 'User not found' });
    u.points += Number(points);
    await u.save();
    res.json({ msg: `Added ${points} points to ${username}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// 7) Update Quantity (admin)
app.post('/api/admin/update-quantity', authorize, isAdmin, async (req, res) => {
  try {
    const { name, quantity } = req.body;
    const r = await Reward.findOne({ name });
    if (!r) return res.status(404).json({ msg: 'Reward not found' });
    r.quantity = Number(quantity);
    await r.save();
    res.json({ msg: 'Quantity updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// 8) Add Reward + Upload Image (admin)
app.post(
  '/api/admin/add-reward',
  authorize,
  isAdmin,
  upload.single('image'),
  async (req, res) => {
    try {
      const { name, points, quantity } = req.body;
      const img = req.file.filename;
      const newR = await Reward.create({
        name,
        points:   Number(points),
        quantity: Number(quantity),
        image:    img
      });
      res.json({ msg: 'Reward added', reward: newR });
    } catch (err) {
      console.error(err);
      res.status(500).json({ msg: 'Server error' });
    }
  }
);

// 9) List All Users (admin)
app.get('/api/all-users', authorize, isAdmin, async (req, res) => {
  const list = await User.find().select('username points role');
  res.json(list);
});

// ─── 8) แลกรางวัล (Redeem) ─────────────────────────────────────────────────
app.post('/api/redeem', authorize, async (req, res) => {
  try {
    const { name } = req.body;
    // หา reward
    const reward = await Reward.findOne({ name });
    if (!reward) return res.status(404).json({ msg: 'Reward not found' });

    // หา user
    const user = await User.findOne({ username: req.user.username });
    if (user.points < reward.points)
      return res.status(400).json({ msg: 'Insufficient points' });
    if (reward.quantity <= 0)
      return res.status(400).json({ msg: 'Out of stock' });

    // ตัดแต้มและ stock
    user.points     -= reward.points;
    reward.quantity -= 1;
    user.history.push({ code: name, date: new Date() });

    // บันทึกทั้งคู่พร้อมกัน
    await Promise.all([ user.save(), reward.save() ]);

    // ตอบกลับพร้อมแต้มและ stock ใหม่
    res.json({
      msg: 'Redeemed successfully',
      points: user.points,
      quantity: reward.quantity
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
