// server.js (Turso Version)
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { createClient } = require("@libsql/client"); // Turso Client
const jwt = require('jsonwebtoken');
const path = require('path');
const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// --- SECURITY CHECKS ---
const SECRET_KEY = process.env.SECRET_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const TURSO_URL = process.env.TURSO_DATABASE_URL;
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN;

if (!SECRET_KEY || !ADMIN_PASSWORD || !TURSO_URL || !TURSO_TOKEN) {
    console.error("❌ Error: .env ဖိုင်တွင် လိုအပ်သော Key များ မပြည့်စုံပါ။");
    console.error("👉 (SECRET_KEY, ADMIN_PASSWORD, TURSO_DATABASE_URL, TURSO_AUTH_TOKEN)");
    process.exit(1);
}

// --- TURSO DATABASE CONNECTION ---
const client = createClient({
    url: TURSO_URL,
    authToken: TURSO_TOKEN,
});

// Table တည်ဆောက်ခြင်း
(async () => {
    try {
        await client.execute(`
            CREATE TABLE IF NOT EXISTS donations (
                dateKey TEXT PRIMARY KEY,
                data TEXT
            )
        `);
        console.log("✅ Connected to Turso Database & Table Checked.");
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

const loginLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 5, message: { error: "Login attempts exceeded." } });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: "Too many requests." } });
app.use('/api/', apiLimiter);

// --- AUTH MIDDLEWARE ---
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

// --- API ROUTES (Async/Await for Turso) ---

// 1. Login
app.post('/api/login', loginLimiter, (req, res) => {
    const { email, password } = req.body;
    if (password === ADMIN_PASSWORD) {
        const token = jwt.sign({ role: 'admin', email: email }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token });
    } else {
        res.status(401).json({ message: "Password မှားယွင်းနေပါသည်" });
    }
});

// 2. Get All Donations
app.get('/api/donations', async (req, res) => {
    try {
        const result = await client.execute("SELECT * FROM donations");
        const allData = {};
        // Turso returns rows in `result.rows`
        result.rows.forEach(row => {
            try { allData[row.dateKey] = JSON.parse(row.data); }
            catch (e) { console.error(`Parsing error for ${row.dateKey}`); }
        });
        res.json(allData);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 3. Save/Update Donation
app.post('/api/donations', authenticateToken, async (req, res) => {
    const { dateKey, type, data } = req.body;
    try {
        const result = await client.execute({
            sql: "SELECT data FROM donations WHERE dateKey = ?",
            args: [dateKey]
        });

        let currentData = (result.rows.length > 0) ? JSON.parse(result.rows[0].data) : {};
        currentData[type] = data;
        const jsonStr = JSON.stringify(currentData);

        if (result.rows.length > 0) {
            await client.execute({
                sql: "UPDATE donations SET data = ? WHERE dateKey = ?",
                args: [jsonStr, dateKey]
            });
        } else {
            await client.execute({
                sql: "INSERT INTO donations (dateKey, data) VALUES (?, ?)",
                args: [dateKey, jsonStr]
            });
        }
        res.json({ message: "Saved", data: currentData });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 4. Delete Donation
app.delete('/api/donations', authenticateToken, async (req, res) => {
    const { dateKey, type, donorId } = req.body;
    try {
        const result = await client.execute({
            sql: "SELECT data FROM donations WHERE dateKey = ?",
            args: [dateKey]
        });

        if (result.rows.length === 0) return res.status(404).json({ message: "Not found" });

        let currentData = JSON.parse(result.rows[0].data);

        if (currentData[type]) {
            if (Array.isArray(currentData[type]) && donorId) {
                currentData[type] = currentData[type].filter(d => d.id !== donorId);
                if (currentData[type].length === 0) delete currentData[type];
            } else {
                delete currentData[type];
            }
        }

        if (Object.keys(currentData).length === 0) {
            await client.execute({
                sql: "DELETE FROM donations WHERE dateKey = ?",
                args: [dateKey]
            });
            res.json({ message: "Deleted fully" });
        } else {
            await client.execute({
                sql: "UPDATE donations SET data = ? WHERE dateKey = ?",
                args: [JSON.stringify(currentData), dateKey]
            });
            res.json({ message: "Deleted specific donor" });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 5. Clear All
app.post('/api/clear-all', authenticateToken, async (req, res) => {
    try {
        await client.execute("DELETE FROM donations");
        res.json({ message: "All data cleared" });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 6. Import Data
app.post('/api/import', authenticateToken, async (req, res) => {
    const importData = req.body;
    const keys = Object.keys(importData);
    if (keys.length === 0) return res.json({ message: "Nothing to import" });

    // Turso supports batch transactions
    const transaction = keys.map(key => {
        return {
            sql: "INSERT INTO donations (dateKey, data) VALUES (?, ?) ON CONFLICT(dateKey) DO UPDATE SET data=excluded.data",
            args: [key, JSON.stringify(importData[key])]
        };
    });

    try {
        await client.batch(transaction, "write");
        res.json({ message: "Import successful", count: keys.length });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Import failed" });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});