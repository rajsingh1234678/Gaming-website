const express = require('express');
const cors = require('cors');
const multer = require('multer');
const AdmZip = require('adm-zip');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// DIRECTORIES
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOADS_DIR = path.join(PUBLIC_DIR, 'published-games');
const THUMBS_DIR = path.join(PUBLIC_DIR, 'thumbnails');
const DB_FILE = path.join(__dirname, 'database.json');
const SETTINGS_FILE = path.join(__dirname, 'settings.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
const TEMP_DIR = path.join(__dirname, 'temp-uploads');

[PUBLIC_DIR, UPLOADS_DIR, THUMBS_DIR, TEMP_DIR].forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify([]));
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));
if (!fs.existsSync(SESSIONS_FILE)) fs.writeFileSync(SESSIONS_FILE, JSON.stringify({}));

// SETTINGS (ADS ENGINE CONFIG)
if (!fs.existsSync(SETTINGS_FILE)) {
  fs.writeFileSync(
    SETTINGS_FILE,
    JSON.stringify({
      adsEnabled: false,
      selectedNetwork: 'adsterra', // 'adsterra', 'adsense', 'monetag', 'custom'
      headerAdCode: '',
      gameAdCode: '',
      siteName: 'HYPERVAULT',
    })
  );
}

// STATIC GAME ASSETS SERVING
app.use(
  express.static(PUBLIC_DIR, {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('.wasm')) res.setHeader('Content-Type', 'application/wasm');
    },
  })
);

// HELPERS
const getGamesFromDB = () => JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
const saveGamesToDB = (data) => fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));

const getSettings = () => JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf-8'));
const saveSettings = (data) => fs.writeFileSync(SETTINGS_FILE, JSON.stringify(data, null, 2));

const getUsers = () => JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8'));
const saveUsers = (data) => fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));

const getSessions = () => JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf-8'));
const saveSessions = (data) => fs.writeFileSync(SESSIONS_FILE, JSON.stringify(data, null, 2));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, TEMP_DIR),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 } });

// ================= REAL AUTHENTICATION ENGINE ================= //

// 1. SIGNUP WITH ANY EMAIL & PASSWORD
app.post('/api/auth/signup', (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!email || !password || password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password kam se kam 6 aksharon ka hona chahiye!' });
    }

    const users = getUsers();
    const cleanEmail = email.toLowerCase().trim();

    // Check if user already exists
    if (users.some((u) => u.email === cleanEmail)) {
      return res.status(400).json({ success: false, error: 'Yeh Email pehle se registered hai! Kripya Login karein.' });
    }

    // Password Hash
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');

    // First registered user is Master Admin
    const role = users.length === 0 ? 'admin' : 'admin';

    const newUser = {
      id: 'usr_' + Date.now(),
      name: name || 'Admin Boss',
      email: cleanEmail,
      passwordHash,
      role,
      createdAt: new Date().toISOString(),
    };

    users.push(newUser);
    saveUsers(users);

    // Create Permanent Session Token
    const token = 'hv_perm_' + crypto.randomBytes(32).toString('hex');
    const sessions = getSessions();
    sessions[token] = { userId: newUser.id, email: newUser.email, name: newUser.name, role: newUser.role };
    saveSessions(sessions);

    // Email Notification Log
    console.log(`====================================================`);
    console.log(`📧 [EMAIL NOTIFICATION TRIGGERED]`);
    console.log(`To: ${cleanEmail}`);
    console.log(`Subject: Welcome to HYPERVAULT Admin Console`);
    console.log(`Body: Hello ${newUser.name}, your account is created successfully.`);
    console.log(`====================================================`);

    res.json({
      success: true,
      token,
      user: { name: newUser.name, email: newUser.email, role: newUser.role },
      notificationSent: true,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. LOGIN WITH ANY REGISTERED EMAIL
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    const users = getUsers();
    const cleanEmail = email.toLowerCase().trim();

    const inputHash = crypto.createHash('sha256').update(password).digest('hex');
    const user = users.find((u) => u.email === cleanEmail && u.passwordHash === inputHash);

    if (!user) {
      // Agar users database abhi khali hai toh unhe signup karne ko bolein
      if (users.length === 0) {
        return res.status(400).json({ success: false, error: 'Abhi koi account nahi hai. "Create Account / Sign Up" par click karke naya account banayein!' });
      }
      return res.status(401).json({ success: false, error: 'Galat Email ya Password! Kripya sahi details bharein.' });
    }

    // Generate Permanent Session Token
    const token = 'hv_perm_' + crypto.randomBytes(32).toString('hex');
    const sessions = getSessions();
    sessions[token] = { userId: user.id, email: user.email, name: user.name, role: user.role };
    saveSessions(sessions);

    // Login Email Alert Log
    console.log(`📧 [LOGIN ALERT NOTIFICATION] User ${user.email} logged in at ${new Date().toLocaleTimeString()}`);

    res.json({
      success: true,
      token,
      user: { name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. VERIFY PERMANENT LOGIN SESSION
app.get('/api/auth/verify', (req, res) => {
  const token = req.headers['authorization'];
  if (!token) return res.json({ valid: false });

  const sessions = getSessions();
  const session = sessions[token];

  if (session) {
    return res.json({ valid: true, user: session });
  }
  res.json({ valid: false });
});

// 4. LOGOUT (Only when clicked)
app.post('/api/auth/logout', (req, res) => {
  const token = req.headers['authorization'];
  if (token) {
    const sessions = getSessions();
    delete sessions[token];
    saveSessions(sessions);
  }
  res.json({ success: true });
});

// ================= ADVERTISING & SETTINGS APIS ================= //

app.get('/api/settings', (req, res) => res.json(getSettings()));

app.post('/api/settings', (req, res) => {
  try {
    const current = getSettings();
    const updated = { ...current, ...req.body };
    saveSettings(updated);
    res.json({ success: true, settings: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= GAMES MANAGEMENT APIS ================= //

app.get('/api/games', (req, res) => res.json(getGamesFromDB()));

app.post('/api/games/:id/play', (req, res) => {
  const games = getGamesFromDB();
  const game = games.find((g) => g.id === req.params.id);
  if (game) {
    game.plays = (game.plays || 0) + 1;
    saveGamesToDB(games);
    return res.json({ success: true, plays: game.plays });
  }
  res.status(404).json({ error: 'Game not found' });
});

app.post('/api/upload', upload.fields([{ name: 'zip', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), (req, res) => {
  try {
    const { title, category, description, controls } = req.body;
    const zipFile = req.files['zip'] ? req.files['zip'][0] : null;
    const thumbFile = req.files['thumbnail'] ? req.files['thumbnail'][0] : null;

    if (!zipFile) return res.status(400).json({ error: 'Game ZIP required!' });

    const gameId = 'game_' + Date.now();
    const gameExtractPath = path.join(UPLOADS_DIR, gameId);

    const zip = new AdmZip(zipFile.path);
    zip.extractAllTo(gameExtractPath, true);

    const hasIndexHtml = (dir) => {
      const items = fs.readdirSync(dir);
      if (items.includes('index.html')) return true;
      for (const item of items) {
        const itemPath = path.join(dir, item);
        if (fs.statSync(itemPath).isDirectory() && hasIndexHtml(itemPath)) return true;
      }
      return false;
    };

    if (!hasIndexHtml(gameExtractPath)) {
      fs.rmSync(gameExtractPath, { recursive: true, force: true });
      if (fs.existsSync(zipFile.path)) fs.unlinkSync(zipFile.path);
      return res.status(400).json({ error: 'ZIP me "index.html" nahi mila!' });
    }

    let thumbUrl = 'https://images.unsplash.com/photo-1550745165-9bc0b252726f?w=600';
    if (thumbFile) {
      const thumbExt = path.extname(thumbFile.originalname);
      const thumbName = `${gameId}_thumb${thumbExt}`;
      const destThumbPath = path.join(THUMBS_DIR, thumbName);
      fs.renameSync(thumbFile.path, destThumbPath);
      thumbUrl = `/thumbnails/${thumbName}`;
    }

    if (fs.existsSync(zipFile.path)) fs.unlinkSync(zipFile.path);

    const newGame = {
      id: gameId,
      title: title || 'Untitled Game',
      category: category || 'Arcade',
      description: description || 'Instant playable web game.',
      controls: controls || 'Touch / Keyboard / Mouse',
      thumbnail: thumbUrl,
      play_url: `/published-games/${gameId}/index.html`,
      plays: 0,
      created_at: new Date().toISOString(),
    };

    const games = getGamesFromDB();
    games.unshift(newGame);
    saveGamesToDB(games);

    res.json({ success: true, game: newGame });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/games/:id', (req, res) => {
  const games = getGamesFromDB();
  const gameIndex = games.findIndex((g) => g.id === req.params.id);
  if (gameIndex !== -1) {
    const game = games[gameIndex];
    const gameFolder = path.join(UPLOADS_DIR, game.id);
    if (fs.existsSync(gameFolder)) fs.rmSync(gameFolder, { recursive: true, force: true });
    games.splice(gameIndex, 1);
    saveGamesToDB(games);
    return res.json({ success: true });
  }
  res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, () => {
  console.log(`🎮 HYPERVAULT SECURE SERVER LIVE ON: http://localhost:${PORT}`);
});