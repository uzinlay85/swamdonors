require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { createClient } = require("@libsql/client");
const jwt = require('jsonwebtoken');
const path = require('path');
const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// --- (၁) ပြင်ဆင်ချက် - Render Proxy အတွက် ---
app.set('trust proxy', 1); 

// --- SECURITY CHECKS ---
const SECRET_KEY = process.env.SECRET_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const TURSO_URL = process.env.TURSO_DATABASE_URL;
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN;

if (!SECRET_KEY || !ADMIN_PASSWORD || !TURSO_URL || !TURSO_TOKEN) {
    console.error("❌ Error: .env ဖိုင်မပြည့်စုံပါ။");
    process.exit(1);
}

// --- TURSO DB CONNECTION ---
const client = createClient({
    url: TURSO_URL,
    authToken: TURSO_TOKEN,
    tls: true,
});

(async () => {
    try {
        await client.execute(`
            CREATE TABLE IF NOT EXISTS donations (
                dateKey TEXT PRIMARY KEY,
                data TEXT
            )
        `);
        console.log("✅ Connected to Turso Database.");
    } catch (e) {
        console.error("❌ Database Connection Error:", e);
    }
})();

// --- MIDDLEWARE ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiter
const loginLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 5, message: { error: "Login attempts exceeded." } });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: "Too many requests." } });
app.use('/api/', apiLimiter);

// --- AUTH ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// --- ROUTES ---
app.post('/api/login', loginLimiter, (req, res) => {
    const { email, password } = req.body;
    if (password === ADMIN_PASSWORD) {
        const token = jwt.sign({ role: 'admin', email: email }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token });
    } else {
        res.status(401).json({ message: "Password မှားယွင်းနေပါသည်" });
    }
});

app.get('/api/donations', async (req, res) => {
    try {
        const result = await client.execute("SELECT * FROM donations");
        const allData = {};
        result.rows.forEach(row => {
            try { allData[row.dateKey] = JSON.parse(row.data); }
            catch (e) {}
        });
        res.json(allData);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/donations', authenticateToken, async (req, res) => {
    const { dateKey, type, data } = req.body;
    try {
        const result = await client.execute({ sql: "SELECT data FROM donations WHERE dateKey = ?", args: [dateKey] });
        let currentData = (result.rows.length > 0) ? JSON.parse(result.rows[0].data) : {};
        currentData[type] = data;
        const jsonStr = JSON.stringify(currentData);

        if (result.rows.length > 0) {
            await client.execute({ sql: "UPDATE donations SET data = ? WHERE dateKey = ?", args: [jsonStr, dateKey] });
        } else {
            await client.execute({ sql: "INSERT INTO donations (dateKey, data) VALUES (?, ?)", args: [dateKey, jsonStr] });
        }
        res.json({ message: "Saved", data: currentData });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/donations', authenticateToken, async (req, res) => {
    const { dateKey, type, donorId } = req.body;
    try {
        const result = await client.execute({ sql: "SELECT data FROM donations WHERE dateKey = ?", args: [dateKey] });
        if (result.rows.length === 0) return res.status(404).json({ message: "Not found" });
        let currentData = JSON.parse(result.rows[0].data);

        if (currentData[type]) {
            if (Array.isArray(currentData[type]) && donorId) {
                currentData[type] = currentData[type].filter(d => d.id !== donorId);
                if (currentData[type].length === 0) delete currentData[type];
            } else { delete currentData[type]; }
        }

        if (Object.keys(currentData).length === 0) {
            await client.execute({ sql: "DELETE FROM donations WHERE dateKey = ?", args: [dateKey] });
        } else {
            await client.execute({ sql: "UPDATE donations SET data = ? WHERE dateKey = ?", args: [JSON.stringify(currentData), dateKey] });
        }
        res.json({ message: "Deleted" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/clear-all', authenticateToken, async (req, res) => {
    try { await client.execute("DELETE FROM donations"); res.json({ message: "Cleared" }); } 
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/import', authenticateToken, async (req, res) => {
    const importData = req.body;
    const keys = Object.keys(importData);
    if (keys.length === 0) return res.json({ message: "Nothing to import" });
    const transaction = keys.map(key => ({
        sql: "INSERT INTO donations (dateKey, data) VALUES (?, ?) ON CONFLICT(dateKey) DO UPDATE SET data=excluded.data",
        args: [key, JSON.stringify(importData[key])]
    }));
    try { await client.batch(transaction, "write"); res.json({ message: "Success" }); } 
    catch (e) { res.status(500).json({ error: "Import failed" }); }
});


app.listen(PORT, () => { console.log(`Server running on port ${PORT}`); });
