const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'amjad_ultimate_secure_key_2026';
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// حماية صارمة ضد هجمات القوة الغاشمة وتخمني كلمة المرور (أقصى حد 5 محاولات)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'تم تجاوز الحد المسموح لمحاولات الدخول. تم حظر الطلبات مؤقتاً لحماية النظام.' }
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
        price TEXT,
        currency TEXT DEFAULT 'YER',
        category TEXT DEFAULT 'wedding',
        image TEXT,
        available INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    const defaultHash = await bcrypt.hash('77W7@', 12);
    db.run(
        `INSERT INTO users (username, password) VALUES ('admin', ?)
         ON CONFLICT(username) DO UPDATE SET password = ?`,
        [defaultHash, defaultHash]
    );
});

function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'غير مصرح - يرجى تسجيل الدخول' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'انتهت صلاحية الجلسة، أعد تسجيل الدخول' });
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
        if (err || !user) return res.status(400).json({ message: 'بيانات الدخول خاطئة' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ message: 'بيانات الدخول خاطئة' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token });
    });
});

app.post('/api/products', authMiddleware, (req, res) => {
    const { title, description, price, currency, category, image, available } = req.body;
    db.run(
        `INSERT INTO products (title, description, price, currency, category, image, available) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [title, description, price, currency || 'YER', category || 'wedding', image, available ? 1 : 0],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID, message: 'تم حفظ ونشر المنتج بنجاح' });
        }
    );
});

app.put('/api/products/:id', authMiddleware, (req, res) => {
    const { title, description, price, currency, category, image } = req.body;
    const { id } = req.params;

    const query = image 
        ? `UPDATE products SET title = ?, description = ?, price = ?, currency = ?, category = ?, image = ? WHERE id = ?`
        : `UPDATE products SET title = ?, description = ?, price = ?, currency = ?, category = ? WHERE id = ?`;
    
    const params = image ? [title, description, price, currency, category, image, id] : [title, description, price, currency, category, id];

    db.run(query, params, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'تم تعديل المنتج بنجاح' });
    });
});

app.delete('/api/products/:id', authMiddleware, (req, res) => {
    db.run('DELETE FROM products WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'تم الحذف بنجاح' });
    });
});

app.listen(PORT, () => console.log(`Secure Server running on port ${PORT}`));
