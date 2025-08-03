// server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

const SECRET = process.env.SECRET_KEY || 'my-secret-key';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // ตั้งค่าใน Render Dashboard → Environment
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// helper สำหรับ query
async function dbQuery(text, params = []) {
  const res = await pool.query(text, params);
  return res;
}

// --------------------------------------------
// 1) เตรียมตาราง (run ทีเดียวก่อน deploy)
// --------------------------------------------
// CREATE TABLE users (
//   id SERIAL PRIMARY KEY,
//   username TEXT UNIQUE NOT NULL,
//   password TEXT NOT NULL,
//   points INTEGER NOT NULL DEFAULT 0,
//   role TEXT NOT NULL DEFAULT 'user'
// );
// CREATE TABLE history (
//   id SERIAL PRIMARY KEY,
//   user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
//   action TEXT NOT NULL,
//   created_at TIMESTAMP NOT NULL DEFAULT now()
// );
// CREATE TABLE rewards (
//   name TEXT PRIMARY KEY,
//   points INTEGER NOT NULL,
//   quantity INTEGER NOT NULL,
//   image TEXT NOT NULL
// );

// --------------------------------------------
// 2) API: สมัครสมาชิก
// --------------------------------------------
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    // ตรวจว่ามีแล้วหรือไม่
    const { rows } = await dbQuery('SELECT 1 FROM users WHERE username=$1', [username]);
    if (rows.length) return res.status(400).json({ msg: 'มีผู้ใช้นี้แล้ว' });

    const hashed = await bcrypt.hash(password, 10);
    await dbQuery(
      `INSERT INTO users(username, password) VALUES($1, $2)`,
      [username, hashed]
    );
    res.json({ msg: 'สมัครเรียบร้อย' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'เกิดข้อผิดพลาดภายใน' });
  }
});

// --------------------------------------------
// 3) API: ล็อกอิน
// --------------------------------------------
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const { rows } = await dbQuery('SELECT id, password FROM users WHERE username=$1', [username]);
    if (!rows.length) return res.status(401).json({ msg: 'ชื่อผู้ใช้หรือรหัสผ่านผิด' });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ msg: 'ชื่อผู้ใช้หรือรหัสผ่านผิด' });

    const token = jwt.sign({ userId: user.id }, SECRET, { expiresIn: '2h' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'เกิดข้อผิดพลาดภายใน' });
  }
});

// --------------------------------------------
// 4) Middleware: ตรวจ JWT
// --------------------------------------------
function auth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/, '');
  if (!token) return res.status(401).json({ msg: 'ไม่พบ token' });

  try {
    const payload = jwt.verify(token, SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    res.status(403).json({ msg: 'Token ไม่ถูกต้อง' });
  }
}

// --------------------------------------------
// 5) API: ดึงข้อมูลโปรไฟล์ผู้ใช้ (me)
// --------------------------------------------
app.get('/api/me', auth, async (req, res) => {
  try {
    const { rows } = await dbQuery(
      `SELECT username, points, role FROM users WHERE id=$1`,
      [req.userId]
    );
    if (!rows.length) return res.status(404).json({ msg: 'ไม่พบผู้ใช้' });
    const user = rows[0];

    const history = (await dbQuery(
      `SELECT action, created_at FROM history WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20`,
      [req.userId]
    )).rows;

    res.json({ username: user.username, points: user.points, role: user.role, history });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'เกิดข้อผิดพลาดภายใน' });
  }
});

// --------------------------------------------
// 6) API: โหลดของรางวัล
// --------------------------------------------
app.get('/api/rewards', async (req, res) => {
  try {
    const { rows } = await dbQuery(`SELECT name, points, quantity, image FROM rewards`);
    // แปลงเป็น object
    const obj = {};
    for (const r of rows) obj[r.name] = r;
    res.json(obj);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'เกิดข้อผิดพลาดภายใน' });
  }
});

// --------------------------------------------
// 7) API: แลกรางวัล (redeem)
// --------------------------------------------
app.post('/api/redeem', auth, async (req, res) => {
  const { rewardName } = req.body;
  try {
    // ดึง reward
    const rewardRes = await dbQuery(
      `SELECT points, quantity FROM rewards WHERE name=$1 FOR UPDATE`,
      [rewardName]
    );
    if (!rewardRes.rows.length) return res.status(404).json({ msg: 'ไม่พบของรางวัล' });
    const { points: cost, quantity } = rewardRes.rows[0];
    if (quantity <= 0) return res.status(400).json({ msg: 'ของรางวัลหมดแล้ว' });

    // ดึง user แต้ม
    const userRes = await dbQuery(
      `SELECT points FROM users WHERE id=$1 FOR UPDATE`,
      [req.userId]
    );
    const userPoints = userRes.rows[0].points;
    if (userPoints < cost) return res.status(400).json({ msg: 'แต้มไม่เพียงพอ' });

    // ทำ transaction ลดแต้ม-ลดจำนวน
    await dbQuery('BEGIN');
    await dbQuery(`UPDATE users SET points = points - $1 WHERE id=$2`, [cost, req.userId]);
    await dbQuery(`UPDATE rewards SET quantity = quantity - 1 WHERE name=$1`, [rewardName]);
    await dbQuery(
      `INSERT INTO history(user_id, action) VALUES($1, $2)`,
      [req.userId, `redeem:${rewardName}`]
    );
    await dbQuery('COMMIT');

    res.json({ msg: 'แลกของรางวัลสำเร็จ!' });
  } catch (err) {
    await dbQuery('ROLLBACK');
    console.error(err);
    res.status(500).json({ msg: 'เกิดข้อผิดพลาดภายใน' });
  }
});

// --------------------------------------------
// 8) API: แอดมินเพิ่มแต้มให้ผู้ใช้
// --------------------------------------------
app.post('/api/admin/add-points', auth, async (req, res) => {
  const { username, points } = req.body;
  try {
    // ตรวจสิทธิ์แอดมิน
    const me = (await dbQuery(`SELECT role FROM users WHERE id=$1`, [req.userId])).rows[0];
    if (me.role !== 'admin') return res.status(403).json({ msg: 'คุณไม่ใช่แอดมิน' });

    await dbQuery(
      `UPDATE users SET points = points + $1 WHERE username=$2`,
      [points, username]
    );
    res.json({ msg: `เพิ่มแต้มให้ ${username} เรียบร้อยแล้ว` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'เกิดข้อผิดพลาดภายใน' });
  }
});

// --------------------------------------------
// 9) API: ลืมรหัสผ่าน (reset-password)
// --------------------------------------------
app.post('/api/reset-password', async (req, res) => {
  const { username, newPassword } = req.body;
  try {
    const { rows } = await dbQuery('SELECT id FROM users WHERE username=$1', [username]);
    if (!rows.length) return res.status(404).json({ msg: 'ไม่พบผู้ใช้นี้' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await dbQuery(`UPDATE users SET password=$1 WHERE username=$2`, [hashed, username]);
    res.json({ msg: 'เปลี่ยนรหัสผ่านเรียบร้อยแล้ว' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'เกิดข้อผิดพลาดภายใน' });
  }
});

// --------------------------------------------
// สั่งให้ server ฟัง port
// --------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
