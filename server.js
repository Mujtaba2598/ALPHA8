const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

const HALAL_ASSETS = [
    'BTCUSDT', 'ETHUSDT', 'BNBUSDT', 'SOLUSDT', 'ADAUSDT',
    'XRPUSDT', 'DOTUSDT', 'LINKUSDT', 'MATICUSDT', 'AVAXUSDT'
];

// ==================== DATA DIRECTORIES ====================
const DATA_DIR = path.join(__dirname, 'data');
const TRADES_DIR = path.join(DATA_DIR, 'trades');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PENDING_FILE = path.join(DATA_DIR, 'pending.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(TRADES_DIR)) fs.mkdirSync(TRADES_DIR, { recursive: true });

// ==================== CREATE / RESET OWNER ACCOUNT ====================
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({}, null, 2));

let users = JSON.parse(fs.readFileSync(USERS_FILE));
const ownerEmail = "mujtabahatif@gmail.com";
const ownerPass = "Mujtabah@2598";

if (!users[ownerEmail]) {
    users[ownerEmail] = {
        email: ownerEmail,
        password: bcrypt.hashSync(ownerPass, 10),
        isOwner: true,
        isApproved: true,
        isBlocked: false,
        apiKey: "",
        secretKey: "",
        createdAt: new Date().toISOString()
    };
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    console.log("✅ Owner account created.");
} else if (!bcrypt.compareSync(ownerPass, users[ownerEmail].password)) {
    users[ownerEmail].password = bcrypt.hashSync(ownerPass, 10);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    console.log("✅ Owner password reset.");
}

if (!fs.existsSync(PENDING_FILE)) fs.writeFileSync(PENDING_FILE, JSON.stringify({}, null, 2));
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, JSON.stringify({}, null, 2));

// ==================== HELPER FUNCTIONS ====================
function readUsers() { return JSON.parse(fs.readFileSync(USERS_FILE)); }
function writeUsers(data) { fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(PENDING_FILE)); }
function writePending(data) { fs.writeFileSync(PENDING_FILE, JSON.stringify(data, null, 2)); }
function readOrders() { return JSON.parse(fs.readFileSync(ORDERS_FILE)); }
function writeOrders(data) { fs.writeFileSync(ORDERS_FILE, JSON.stringify(data, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}
function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = parts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: '🕋 HALAL Trading Bot', halalAssets: HALAL_ASSETS.length });
});

// ==================== AUTHENTICATION ====================
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Required' });
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'Exists' });
    const pending = readPending();
    if (pending[email]) return res.status(400). json({ success: false, message: 'Pending' });
    pending[email] = { email, password: bcrypt.hashSync(password, 10), requestedAt: new Date().toISOString() };
    writePending(pending);
    res.json({ success: true, message: 'Request sent to owner' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    if (!user) {
        if (readPending()[email]) return res.status(401).json({ success: false, message: 'Pending approval' });
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Blocked' });
    const token = jwt.sign({ email, isOwner: user.isOwner }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== BINANCE API ====================
const BINANCE_API = 'https://api.binance.com';
const BINANCE_TESTNET = 'https://testnet.binance.vision';

function cleanKey(k) { return k ? k.replace(/[\s\n\r\t]+/g, '').trim() : ""; }

async function binanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET', testnet = false) {
    const baseUrl = testnet ? BINANCE_TESTNET : BINANCE_API;
    const timestamp = Date.now();
    const allParams = { ...params, timestamp, recvWindow: 5000 };
    const queryString = Object.keys(allParams).sort().map(k => `${k}=${allParams[k]}`).join('&');
    const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');
    const url = `${baseUrl}${endpoint}?${queryString}&signature=${signature}`;
    const response = await axios({ method, url, headers: { 'X-MBX-APIKEY': apiKey }, timeout: 10000 });
    return response.data;
}

async function getSpotBalance(apiKey, secretKey, testnet = false) {
    try {
        const acc = await binanceRequest(apiKey, secretKey, '/api/v3/account', {}, 'GET', testnet);
        const usdt = acc.balances.find(b => b.asset === 'USDT');
        return parseFloat(usdt?.free || 0);
    } catch { return 0; }
}
async function getFundingBalance(apiKey, secretKey, testnet = false) {
    try {
        const timestamp = Date.now();
        const queryString = `timestamp=${timestamp}`;
        const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');
        const baseUrl = testnet ? BINANCE_TESTNET : BINANCE_API;
        const url = `${baseUrl}/sapi/v1/asset/get-funding-asset?${queryString}&signature=${signature}`;
        const response = await axios({ method: 'POST', url, headers: { 'X-MBX-APIKEY': apiKey }, timeout: 10000 });
        const usdtAsset = response.data.find(a => a.asset === 'USDT');
        return parseFloat(usdtAsset?.free || 0);
    } catch { return 0; }
}
async function getCurrentPrice(symbol, testnet = false) {
    const baseUrl = testnet ? BINANCE_TESTNET : BINANCE_API;
    const res = await axios.get(`${baseUrl}/api/v3/ticker/price?symbol=${symbol}`);
    return parseFloat(res.data.price);
}
async function placeLimitOrder(apiKey, secretKey, symbol, side, quantity, price, testnet = false) {
    return await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol, side, type: 'LIMIT', timeInForce: 'GTC',
        quantity: quantity.toFixed(6), price: price.toFixed(2)
    }, 'POST', testnet);
}
async function checkOrderStatus(apiKey, secretKey, symbol, orderId, testnet = false) {
    return await binanceRequest(apiKey, secretKey, '/api/v3/order', { symbol, orderId }, 'GET', testnet);
}
async function cancelOrder(apiKey, secretKey, symbol, orderId, testnet = false) {
    return await binanceRequest(apiKey, secretKey, '/api/v3/order', { symbol, orderId }, 'DELETE', testnet);
}

// ==================== DIAGNOSTIC ENDPOINT (TELLS YOU WHY KEYS FAIL) ====================
app.post('/api/test-binance-keys', authenticate, async (req, res) => {
    const { apiKey, secretKey, accountType } = req.body;
    const useTestnet = accountType === 'testnet';
    const baseUrl = useTestnet ? BINANCE_TESTNET : BINANCE_API;
    try {
        const timestamp = Date.now();
        const queryString = `timestamp=${timestamp}&recvWindow=5000`;
        const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');
        const url = `${baseUrl}/api/v3/account?${queryString}&signature=${signature}`;
        const response = await axios({
            method: 'GET',
            url,
            headers: { 'X-MBX-APIKEY': apiKey },
            timeout: 10000
        });
        res.json({ success: true, message: '✅ API keys are valid!', data: response.data });
    } catch (error) {
        const binanceMsg = error.response?.data?.msg || error.message;
        res.json({ success: false, message: `❌ Binance error: ${binanceMsg}` });
    }
});

// ==================== API KEY MANAGEMENT ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    let { apiKey, secretKey, accountType } = req.body;
    if (!apiKey || !secretKey) return res.status(400).json({ success: false, message: 'Both keys required' });
    const cleanApi = cleanKey(apiKey);
    const cleanSecret = cleanKey(secretKey);
    const testnet = accountType === 'testnet';
    try {
        const spot = await getSpotBalance(cleanApi, cleanSecret, testnet);
        const funding = await getFundingBalance(cleanApi, cleanSecret, testnet);
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        res.json({ success: true, message: `Saved. Spot: ${spot} USDT, Funding: ${funding} USDT`, spotBalance: spot, fundingBalance: funding });
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid API keys (check permissions)' });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) return res.status(400).json({ success: false, message: 'No API keys saved' });
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const testnet = accountType === 'testnet';
    try {
        const spot = await getSpotBalance(apiKey, secretKey, testnet);
        const funding = await getFundingBalance(apiKey, secretKey, testnet);
        res.json({ success: true, spotBalance: spot, fundingBalance: funding, totalBalance: spot + funding });
    } catch {
        res.status(401).json({ success: false, message: 'Connection failed – invalid keys or permissions' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) return res.json({ success: false, message: 'No keys' });
    res.json({ success: true, apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

app.post('/api/get-balance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) return res.json({ success: false, message: 'No API keys' });
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const testnet = accountType === 'testnet';
    const spot = await getSpotBalance(apiKey, secretKey, testnet);
    const funding = await getFundingBalance(apiKey, secretKey, testnet);
    res.json({ success: true, spotBalance: spot, fundingBalance: funding, total: spot + funding });
});

// ==================== TRADING ENGINE ====================
const activeSessions = new Map();
let assetIndex = 0;
function nextAsset() {
    const a = HALAL_ASSETS[assetIndex];
    assetIndex = (assetIndex + 1) % HALAL_ASSETS.length;
    return a;
}

app.post('/api/start-trading', authenticate, async (req, res) => {
    const { investmentAmount, profitPercent, timeLimitHours, accountType } = req.body;
    if (investmentAmount < 10) return res.status(400).json({ success: false, message: 'Min $10' });
    if (profitPercent < 0.1 || profitPercent > 5) return res.status(400).json({ success: false, message: 'Profit 0.1-5%' });
    if (timeLimitHours < 1 || timeLimitHours > 168) return res.status(400).json({ success: false, message: 'Time 1-168h' });

    const user = readUsers()[req.user.email];
    if (!user?.apiKey) return res.status(400).json({ success: false, message: 'Add API keys first' });
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const testnet = accountType === 'testnet';

    try {
        const spot = await getSpotBalance(apiKey, secretKey, testnet);
        const funding = await getFundingBalance(apiKey, secretKey, testnet);
        if (spot + funding < investmentAmount) return res.status(400).json({ success: false, message: 'Insufficient balance' });
    } catch {
        return res.status(401).json({ success: false, message: 'Cannot verify balance' });
    }

    const sessionId = crypto.randomBytes(16).toString('hex');
    const symbol = nextAsset();
    const price = await getCurrentPrice(symbol, testnet);
    const buyPrice = price * 0.998;
    const quantity = investmentAmount / buyPrice;

    try {
        const order = await placeLimitOrder(apiKey, secretKey, symbol, 'BUY', quantity, buyPrice, testnet);
        const sessionData = {
            userId: req.user.email, symbol, buyOrderId: order.orderId, buyPrice, quantity,
            investmentAmount, profitPercent, timeLimitHours, startTime: Date.now(),
            testnet, status: 'BUY_ORDER_PLACED'
        };
        activeSessions.set(sessionId, sessionData);
        const orders = readOrders();
        orders[sessionId] = sessionData;
        writeOrders(orders);
        res.json({ success: true, sessionId, message: `✅ Limit buy order: ${quantity.toFixed(6)} ${symbol} @ ${buyPrice}` });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    activeSessions.delete(sessionId);
    res.json({ success: true, message: 'Stopped' });
});

app.post('/api/trade-status', authenticate, (req, res) => {
    const session = activeSessions.get(req.body.sessionId);
    if (!session) return res.json({ success: true, active: false });
    const elapsed = (Date.now() - session.startTime) / (1000 * 3600);
    const remaining = Math.max(0, session.timeLimitHours - elapsed);
    res.json({ success: true, active: true, symbol: session.symbol, status: session.status, timeRemaining: remaining });
});

// Background order checker
setInterval(async () => {
    for (const [sid, trade] of activeSessions) {
        try {
            const user = readUsers()[trade.userId];
            if (!user?.apiKey) continue;
            const apiKey = decrypt(user.apiKey);
            const secretKey = decrypt(user.secretKey);

            if (trade.status === 'BUY_ORDER_PLACED') {
                const order = await checkOrderStatus(apiKey, secretKey, trade.symbol, trade.buyOrderId, trade.testnet);
                if (order.status === 'FILLED') {
                    const fillPrice = parseFloat(order.price);
                    const filledQty = parseFloat(order.executedQty);
                    const sellPrice = fillPrice * (1 + trade.profitPercent / 100);
                    const sellOrder = await placeLimitOrder(apiKey, secretKey, trade.symbol, 'SELL', filledQty, sellPrice, trade.testnet);
                    trade.status = 'SELL_ORDER_PLACED';
                    trade.sellOrderId = sellOrder.orderId;
                    trade.entryPrice = fillPrice;
                    trade.filledQty = filledQty;
                }
            } else if (trade.status === 'SELL_ORDER_PLACED') {
                const order = await checkOrderStatus(apiKey, secretKey, trade.symbol, trade.sellOrderId, trade.testnet);
                if (order.status === 'FILLED') {
                    const exitPrice = parseFloat(order.price);
                    const profit = (exitPrice - trade.entryPrice) * trade.filledQty;
                    const profitPercent = (profit / trade.investmentAmount) * 100;
                    const historyFile = path.join(TRADES_DIR, trade.userId.replace(/[^a-z0-9]/gi, '_') + '.json');
                    let history = [];
                    if (fs.existsSync(historyFile)) history = JSON.parse(fs.readFileSync(historyFile));
                    history.unshift({
                        symbol: trade.symbol, entryPrice: trade.entryPrice, exitPrice,
                        quantity: trade.filledQty, profit, profitPercent, timestamp: new Date().toISOString()
                    });
                    fs.writeFileSync(historyFile, JSON.stringify(history, null, 2));
                    activeSessions.delete(sid);
                }
            }
            if (Date.now() - trade.startTime > trade.timeLimitHours * 3600000) {
                if (trade.buyOrderId) await cancelOrder(apiKey, secretKey, trade.symbol, trade.buyOrderId, trade.testnet).catch(()=>{});
                if (trade.sellOrderId) await cancelOrder(apiKey, secretKey, trade.symbol, trade.sellOrderId, trade.testnet).catch(()=>{});
                activeSessions.delete(sid);
            }
        } catch (err) { console.error(err.message); }
    }
}, 30000);

app.get('/api/trade-history', authenticate, (req, res) => {
    const file = path.join(TRADES_DIR, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
    if (!fs.existsSync(file)) return res.json({ success: true, trades: [] });
    res.json({ success: true, trades: JSON.parse(fs.readFileSync(file)) });
});

app.get('/api/halal-assets', authenticate, (req, res) => {
    res.json({ success: true, assets: HALAL_ASSETS });
});

// ==================== ADMIN ENDPOINTS ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    const list = Object.keys(pending).map(e => ({ email: e, requestedAt: pending[e].requestedAt }));
    res.json({ success: true, pending: list });
});
app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = {
        email, password: pending[email].password, isOwner: false, isApproved: true,
        isBlocked: false, apiKey: "", secretKey: "", createdAt: new Date().toISOString()
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `Approved ${email}` });
});
app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `Rejected ${email}` });
});
app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `${email} is now ${users[email].isBlocked ? 'BLOCKED' : 'ACTIVE'}` });
});
app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(e => ({
        email: e, hasApiKeys: !!users[e].apiKey, isOwner: users[e].isOwner,
        isApproved: users[e].isApproved, isBlocked: users[e].isBlocked
    }));
    res.json({ success: true, users: list });
});
app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const balances = {};
    for (const [email, u] of Object.entries(users)) {
        if (!u.apiKey) { balances[email] = { spot: 0, funding: 0, total: 0, hasKeys: false }; continue; }
        try {
            const apiKey = decrypt(u.apiKey);
            const secretKey = decrypt(u.secretKey);
            const spot = await getSpotBalance(apiKey, secretKey, false);
            const funding = await getFundingBalance(apiKey, secretKey, false);
            balances[email] = { spot, funding, total: spot + funding, hasKeys: true };
        } catch { balances[email] = { spot: 0, funding: 0, total: 0, hasKeys: true, error: true }; }
    }
    res.json({ success: true, balances });
});
app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const allTrades = {};
    const files = fs.readdirSync(TRADES_DIR);
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(TRADES_DIR, file)));
        allTrades[userId] = trades;
    }
    res.json({ success: true, trades: allTrades });
});
app.post('/api/change-password', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];
    if (!bcrypt.compareSync(currentPassword, owner.password)) return res.status(401).json({ success: false, message: 'Wrong current password' });
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed' });
});

// ==================== SERVE FRONTEND ====================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🕋 HALAL TRADING BOT`);
    console.log(`Owner: mujtabahatif@gmail.com / Mujtabah@2598`);
    console.log(`Port: ${PORT}`);
});
