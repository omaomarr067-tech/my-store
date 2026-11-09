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
app.use(express.json({ limit: '10mb' })); // استيعاب رفع الصور بصيغة base64
app.use(express.static(path.join(__dirname, 'public')));

// حماية محاولات تسجيل الدخول
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15, // رفع حد المحاولات لتجنب الحظر أثناء التجرية
    message: { error: 'تجاوزت حد محاولات تسجيل الدخول. انتظر 15 دقيقة.' }
});

const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error('خطأ في الاتصال بقاعدة البيانات:', err);
    else console.log('تم الاتصال بقاعدة البيانات بنجاح.');
});

db.serialize(async () => {
    // إنشاء جدول المنتجات
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        price TEXT,
        category TEXT DEFAULT 'wedding',
        image TEXT,
        available INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // إنشاء جدول المستخدمين
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    // التأكد من وجود الحساب الافتراضي admin / 77W7@ وتحديث كلمة المرور
    const defaultHash = await bcrypt.hash('77W7@', 10);
    db.run(
        `INSERT INTO users (username, password) VALUES ('admin', ?)
         ON CONFLICT(username) DO UPDATE SET password = ?`,
        [defaultHash, defaultHash],
        (err) => {
            if (err) console.error('خطأ في إعداد حساب الأدمن:', err);
            else console.log('حساب الإدارة (admin / 77W7@) جاهز للاستخدام.');
        }
    );
});

// الوسيط للتحقق من التوكن (Authorization)
function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'غير مصرح بالدخول' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'التوكن غير صالحة أو منتهية' });
        req.user = user;
        next();
    });
}

// 1. جلب كافة المنتجات
app.get('/api/products', (req, res) => {
    db.all('SELECT * FROM products ORDER BY id DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// 2. تسجيل دخول الإدارة
app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ message: 'بيانات الدخول خاطئة' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ message: 'بيانات الدخول خاطئة' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token });
    });
});

// 3. إضافة منتج جديد
app.post('/api/products', authMiddleware, (req, res) => {
    const { title, description, price, category, image, available } = req.body;
    db.run(
        `INSERT INTO products (title, description, price, category, image, available) VALUES (?, ?, ?, ?, ?, ?)`,
        [title, description, price, category || 'wedding', image, available !== undefined ? (available ? 1 : 0) : 1],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID, message: 'تم حفظ المنتج بنجاح' });
        }
    );
});

// 4. تعديل منتج قائم
app.put('/api/products/:id', authMiddleware, (req, res) => {
    const { title, description, price, category, image } = req.body;
    const { id } = req.params;

    if (image) {
        db.run(
            `UPDATE products SET title = ?, description = ?, price = ?, category = ?, image = ? WHERE id = ?`,
            [title, description, price, category || 'wedding', image, id],
            function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ message: 'تم تعديل المنتج بنجاح' });
            }
        );
    } else {
        db.run(
            `UPDATE products SET title = ?, description = ?, price = ?, category = ? WHERE id = ?`,
            [title, description, price, category || 'wedding', id],
            function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ message: 'تم تعديل المنتج بنجاح' });
            }
        );
    }
});

// 5. حذف منتج
app.delete('/api/products/:id', authMiddleware, (req, res) => {
    db.run('DELETE FROM products WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'تم الحذف بنجاح' });
    });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
