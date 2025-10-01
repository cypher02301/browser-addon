const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// configure multer to save uploads to uploads/ dir
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

function is21OrOlder(dobStr) {
  const dob = new Date(dobStr);
  if (isNaN(dob)) return false;
  const now = new Date();
  const age = now.getFullYear() - dob.getFullYear() - (now < new Date(now.getFullYear(), dob.getMonth(), dob.getDate()) ? 1 : 0);
  return age >= 21;
}

app.post('/api/verify', upload.single('idImage'), (req, res) => {
  const { name, dob } = req.body;
  if (!name || !dob) {
    return res.status(400).json({ success: false, message: 'Missing name or date of birth' });
  }
  const ageOk = is21OrOlder(dob);
  if (!ageOk) {
    return res.json({ success: false, message: 'User is under 21' });
  }
  // save file path info if uploaded
  const savedPath = req.file ? req.file.path : null;
  res.json({ success: true, message: 'User verified as 21+', file: savedPath });
});

app.listen(PORT, () => console.log(`KYC server running on port ${PORT}`));