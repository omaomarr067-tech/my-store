const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'amjad_super_secret_key_2026';
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10mb' })); // استيعاب الصور المرفوعة
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'تجاوزت حد محاولات تسجيل الدخول. انتظر 15 دقيقة.' }
});

const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error('خطأ قاعدة البيانات:', err);
    else console.log('تم الاتصال بقاعدة البيانات بنجاح.');
});

db.serialize(async () => {
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        price REAL,
        category TEXT,
        image_data TEXT,
        available INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    const defaultHash = await bcrypt.hash('77W7@', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password) VALUES ('admin', ?)`, [defaultHash]);
});

function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'غير مصرح بالدخول' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'التوكن غير صالحة' });
        req.user = user;
        next();
    });
}

app.get('/api/products', (req, res) => {
    db.all('SELECT * FROM products ORDER BY id DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'بيانات الدخول خاطئة' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'بيانات الدخول خاطئة' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token });
    });
});

app.post('/api/products', authMiddleware, (req, res) => {
    const { title, description, price, category, image_data, available } = req.body;
    db.run(
        `INSERT INTO products (title, description, price, category, image_data, available) VALUES (?, ?, ?, ?, ?, ?)`,
        [title, description, price, category, image_data, available ? 1 : 0],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID, message: 'تم حفظ المنتج بنجاح' });
        }
    );
});

app.delete('/api/products/:id', authMiddleware, (req, res) => {
    db.run('DELETE FROM products WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'تم الحذف بنجاح' });
    });
});

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));