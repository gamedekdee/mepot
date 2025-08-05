// src/seed.js
require('dotenv').config();
const mongoose = require('mongoose');

// ถ้าโมเดลของคุณอยู่ใน server.js ให้ย้ายส่วนนี้มาเป็นไฟล์แยก หรือ
// ให้ adjust path ตามที่ export โมเดลในโปรเจกต์จริงของคุณ
const UserSchema = new mongoose.Schema({ username: String, password: String, points: Number });
const CodeSchema = new mongoose.Schema({ code: String, points: Number });
const RewardSchema = new mongoose.Schema({
  name: String,
  points: Number,
  quantity: Number
});

const Code   = mongoose.model('Code', CodeSchema);
const Reward = mongoose.model('Reward', RewardSchema);

async function seed() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);

    // ลบของเก่าทั้งหมด (ถ้ามี) เพื่อรีเซ็ต
    await Code.deleteMany({});
    await Reward.deleteMany({});

    // ใส่ตัวอย่างโค้ดแลกแต้ม
    await Code.insertMany([
      { code: "WELCOME10", points: 10 },
      { code: "SUMMER20",  points: 20 },
      { code: "FALL30",    points: 30 }
    ]);

    // ใส่ตัวอย่างรางวัล
    await Reward.insertMany([
      { name: "Coffee Mug", points: 100, quantity: 50 },
      { name: "T-Shirt",    points: 200, quantity: 20 },
      { name: "Sticker",    points: 50,  quantity: 100 }
    ]);

    console.log('✅ Seeding done');
  } catch (err) {
    console.error(err);
  } finally {
    mongoose.disconnect();
  }
}

seed();
