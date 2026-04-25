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

// ==================== HALAL ASSETS (Sharia-Compliant) ====================
const HALAL_ASSETS = [
    'BTCUSDT', 'ETHUSDT', 'BNBUSDT', 'SOLUSDT', 'ADAUSDT',
    'XRPUSDT', 'DOTUSDT', 'LINKUSDT', 'MATICUSDT', 'AVAXUSDT'
];

// ==================== CREATE DATA DIRECTORIES ====================
const DATA_DIR = path.join(__dirname, 'data');
const TRADES_DIR = path.join(DATA_DIR, 'trades');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(TRADES_DIR)) fs.mkdirSync(TRADES_DIR, { recursive: true });

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PENDING_FILE = path.join(DATA_DIR, 'pending.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

// Create default owner account
if (!fs.existsSync(USERS_FILE)) {
    const hashedPassword = bcrypt.hashSync('Mujtabah@2598', 10);
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: hashedPassword,
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
    console.log('✅ Created owner account');
}

if (!fs.existsSync(PENDING_FILE)) fs.writeFileSync(PENDING_FILE, JSON.stringify({}, null, 2));
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, JSON.stringify({}, null, 2));

// ==================== HELPER FUNCTIONS ====================
function readUsers() { return JSON.parse(fs.readFileSync(USERS_FILE)); }
function writeUsers(users) { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(PENDING_FILE)); }
function writePending(pending) { fs.writeFileSync(PENDING_FILE, JSON.stringify(pending, null, 2)); }
function readOrders() { return JSON.parse(fs.readFileSync(ORDERS_FILE)); }
function writeOrders(orders) { fs.writeFileSync(ORDERS_FILE, JSON.stringify(orders, null, 2)); }

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

// Logging middleware
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        message: '🕋 100% PURELY HALAL Trading Bot - No Riba, No Gharar, No Maysir',
        timestamp: new Date().toISOString(),
        halalAssets: HALAL_ASSETS.length
    });
});

// ==================== AUTHENTICATION ====================
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    const users = readUsers();
    if (users[email]) {
        return res.status(400).json({ success: false, message: 'User already exists' });
    }

    const pending = readPending();
    if (pending[email]) {
        return res.status(400).json({ success: false, message: 'Request already pending' });
    }

    pending[email] = {
        email,
        password: bcrypt.hashSync(password, 10),
        requestedAt: new Date().toISOString()
    };
    writePending(pending);

    res.json({ success: true, message: 'Registration request sent to owner for approval.' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    console.log(`Login attempt: ${email}`);

    const users = readUsers();
    const user = users[email];

    if (!user) {
        const pending = readPending();
        if (pending[email]) {
            return res.status(401).json({ success: false, message: 'Pending owner approval' });
        }
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    if (!user.isApproved && !user.isOwner) {
        return res.status(401).json({ success: false, message: 'Account not approved by owner' });
    }

    if (user.isBlocked) {
        return res.status(401).json({ success: false, message: 'Account blocked. Contact owner.' });
    }

    const token = jwt.sign({ email, isOwner: user.isOwner }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== BINANCE REAL API ====================
const BINANCE_API = 'https://api.binance.com';
const BINANCE_TESTNET = 'https://testnet.binance.vision';

function cleanKey(key) {
    return key ? key.replace(/[\s\n\r\t]+/g, '').trim() : "";
}

async function makeBinanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET', useTestnet = false) {
    const baseUrl = useTestnet ? BINANCE_TESTNET : BINANCE_API;
    const timestamp = Date.now();
    const allParams = { ...params, timestamp, recvWindow: 5000 };
    const queryString = Object.keys(allParams).sort().map(k => `${k}=${allParams[k]}`).join('&');
    const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');
    const url = `${baseUrl}${endpoint}?${queryString}&signature=${signature}`;

    const response = await axios({
        method,
        url,
        headers: { 'X-MBX-APIKEY': apiKey },
        timeout: 10000
    });
    return response.data;
}

async function getSpotBalance(apiKey, secretKey, useTestnet = false) {
    try {
        const account = await makeBinanceRequest(apiKey, secretKey, '/api/v3/account', {}, 'GET', useTestnet);
        const usdtAsset = account.balances.find(b => b.asset === 'USDT');
        return parseFloat(usdtAsset?.free || 0);
    } catch (error) {
        console.error('Spot balance error:', error.message);
        return 0;
    }
}

async function getFundingBalance(apiKey, secretKey, useTestnet = false) {
    try {
        const timestamp = Date.now();
        const queryString = `timestamp=${timestamp}`;
        const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');
        const baseUrl = useTestnet ? BINANCE_TESTNET : BINANCE_API;
        const url = `${baseUrl}/sapi/v1/asset/get-funding-asset?${queryString}&signature=${signature}`;
        const response = await axios({
            method: 'POST',
            url,
            headers: { 'X-MBX-APIKEY': apiKey },
            timeout: 10000
        });
        const usdtAsset = response.data.find(asset => asset.asset === 'USDT');
        return parseFloat(usdtAsset?.free || 0);
    } catch (error) {
        return 0;
    }
}

async function getCurrentPrice(symbol, useTestnet = false) {
    const baseUrl = useTestnet ? BINANCE_TESTNET : BINANCE_API;
    const response = await axios.get(`${baseUrl}/api/v3/ticker/price?symbol=${symbol}`);
    return parseFloat(response.data.price);
}

async function placeLimitOrder(apiKey, secretKey, symbol, side, quantity, price, useTestnet = false) {
    const order = await makeBinanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol,
        side,
        type: 'LIMIT',
        timeInForce: 'GTC',
        quantity: quantity.toFixed(6),
        price: price.toFixed(2)
    }, 'POST', useTestnet);
    return order;
}

async function checkOrderStatus(apiKey, secretKey, symbol, orderId, useTestnet = false) {
    const order = await makeBinanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol,
        orderId
    }, 'GET', useTestnet);
    return order;
}

async function cancelOrder(apiKey, secretKey, symbol, orderId, useTestnet = false) {
    const result = await makeBinanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol,
        orderId
    }, 'DELETE', useTestnet);
    return result;
}

// ==================== API KEY MANAGEMENT ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    let { apiKey, secretKey, accountType } = req.body;
    if (!apiKey || !secretKey) {
        return res.status(400).json({ success: false, message: 'Both API keys required' });
    }

    const cleanApi = cleanKey(apiKey);
    const cleanSecret = cleanKey(secretKey);
    const useTestnet = accountType === 'testnet';

    try {
        const spotBalance = await getSpotBalance(cleanApi, cleanSecret, useTestnet);
        const fundingBalance = await getFundingBalance(cleanApi, cleanSecret, useTestnet);

        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);

        res.json({
            success: true,
            message: `✅ API keys saved! Spot: ${spotBalance} USDT | Funding: ${fundingBalance} USDT`,
            spotBalance: spotBalance,
            fundingBalance: fundingBalance,
            totalBalance: spotBalance + fundingBalance
        });
    } catch (error) {
        console.error('API key error:', error.message);
        res.status(401).json({ success: false, message: 'Invalid API keys. Check Binance API permissions.' });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const users = readUsers();
    const user = users[req.user.email];

    if (!user.apiKey) {
        return res.status(400).json({ success: false, message: 'No API keys saved. Please add your API keys first.' });
    }

    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useTestnet = accountType === 'testnet';

    try {
        const spotBalance = await getSpotBalance(apiKey, secretKey, useTestnet);
        const fundingBalance = await getFundingBalance(apiKey, secretKey, useTestnet);
        const mode = useTestnet ? 'Testnet' : 'Real Binance';

        res.json({
            success: true,
            spotBalance: spotBalance,
            fundingBalance: fundingBalance,
            totalBalance: spotBalance + fundingBalance,
            message: `✅ Connected to ${mode}! Spot: ${spotBalance.toFixed(2)} USDT | Funding: ${fundingBalance.toFixed(2)} USDT`
        });
    } catch (error) {
        console.error('Connection error:', error.message);
        res.status(401).json({ success: false, message: 'Connection failed. Check your API keys and permissions.' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user.apiKey) {
        return res.json({ success: false, message: 'No API keys saved' });
    }
    res.json({
        success: true,
        apiKey: decrypt(user.apiKey),
        secretKey: decrypt(user.secretKey)
    });
});

// ==================== BALANCE ENDPOINTS ====================
app.post('/api/get-balance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const users = readUsers();
    const user = users[req.user.email];

    if (!user.apiKey) {
        return res.json({ success: false, message: 'No API keys. Please add your Binance API keys.' });
    }

    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useTestnet = accountType === 'testnet';

    try {
        const spotBalance = await getSpotBalance(apiKey, secretKey, useTestnet);
        const fundingBalance = await getFundingBalance(apiKey, secretKey, useTestnet);

        res.json({
            success: true,
            spotBalance: spotBalance,
            fundingBalance: fundingBalance,
            total: spotBalance + fundingBalance
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// ==================== HALAL TRADING ENGINE ====================
const activeTradingSessions = new Map();
let currentAssetIndex = 0;

function getNextHalalAsset() {
    const asset = HALAL_ASSETS[currentAssetIndex];
    currentAssetIndex = (currentAssetIndex + 1) % HALAL_ASSETS.length;
    return asset;
}

app.post('/api/start-trading', authenticate, async (req, res) => {
    const { investmentAmount, profitPercent, timeLimitHours, accountType } = req.body;

    // Halal validation - No gambling, No leverage
    if (investmentAmount < 10) {
        return res.status(400).json({ success: false, message: 'Minimum halal investment is $10' });
    }
    if (profitPercent < 0.1 || profitPercent > 5) {
        return res.status(400).json({ success: false, message: 'Halal profit target must be between 0.1% and 5% per trade' });
    }
    if (timeLimitHours < 1 || timeLimitHours > 168) {
        return res.status(400).json({ success: false, message: 'Time limit must be between 1 and 168 hours' });
    }

    const users = readUsers();
    const user = users[req.user.email];

    if (!user.apiKey) {
        return res.status(400).json({ success: false, message: 'Please add your Binance API keys first' });
    }

    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useTestnet = accountType === 'testnet';

    // Verify sufficient balance
    try {
        const spotBalance = await getSpotBalance(apiKey, secretKey, useTestnet);
        const fundingBalance = await getFundingBalance(apiKey, secretKey, useTestnet);
        const totalBalance = spotBalance + fundingBalance;

        if (totalBalance < investmentAmount) {
            return res.status(400).json({
                success: false,
                message: `Insufficient balance. You have ${totalBalance.toFixed(2)} USDT (Spot: ${spotBalance.toFixed(2)}, Funding: ${fundingBalance.toFixed(2)}), need ${investmentAmount} USDT`
            });
        }
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Cannot verify balance. Check your API keys.' });
    }

    const sessionId = crypto.randomBytes(16).toString('hex');
    const symbol = getNextHalalAsset();
    const currentPrice = await getCurrentPrice(symbol, useTestnet);
    const buyPrice = currentPrice * 0.998; // 0.2% below market (halal limit order)
    const quantity = investmentAmount / buyPrice;

    try {
        const order = await placeLimitOrder(apiKey, secretKey, symbol, 'BUY', quantity, buyPrice, useTestnet);

        const sessionData = {
            userId: req.user.email,
            symbol: symbol,
            buyOrderId: order.orderId,
            buyPrice: buyPrice,
            quantity: quantity,
            investmentAmount: investmentAmount,
            profitPercent: profitPercent,
            timeLimitHours: timeLimitHours,
            startTime: Date.now(),
            useTestnet: useTestnet,
            status: 'BUY_ORDER_PLACED',
            createdAt: new Date().toISOString()
        };

        activeTradingSessions.set(sessionId, sessionData);

        const orders = readOrders();
        orders[sessionId] = sessionData;
        writeOrders(orders);

        const mode = useTestnet ? 'TESTNET (Practice)' : 'REAL BINANCE';
        res.json({
            success: true,
            sessionId: sessionId,
            message: `🕋 HALAL ${mode} ORDER PLACED: Buy ${quantity.toFixed(6)} ${symbol} at ${buyPrice.toFixed(2)} USDT (Limit Order)`
        });

    } catch (error) {
        console.error('Order error:', error.message);
        res.status(500).json({ success: false, message: `Order failed: ${error.message}` });
    }
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const session = activeTradingSessions.get(sessionId);
    if (session) {
        activeTradingSessions.delete(sessionId);
        res.json({ success: true, message: `Trading session ${sessionId} stopped` });
    } else {
        res.json({ success: false, message: 'Session not found' });
    }
});

app.post('/api/trade-status', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const session = activeTradingSessions.get(sessionId);

    if (!session) {
        return res.json({ success: true, active: false });
    }

    const elapsedHours = (Date.now() - session.startTime) / (1000 * 60 * 60);
    const timeRemaining = Math.max(0, session.timeLimitHours - elapsedHours);

    res.json({
        success: true,
        active: true,
        symbol: session.symbol,
        buyPrice: session.buyPrice,
        quantity: session.quantity,
        investmentAmount: session.investmentAmount,
        profitPercent: session.profitPercent,
        status: session.status,
        timeRemaining: timeRemaining,
        createdAt: session.createdAt
    });
});

// ==================== BACKGROUND ORDER CHECKER ====================
setInterval(async () => {
    for (const [sessionId, trade] of activeTradingSessions) {
        try {
            const users = readUsers();
            const user = users[trade.userId];
            if (!user || !user.apiKey) continue;

            const apiKey = decrypt(user.apiKey);
            const secretKey = decrypt(user.secretKey);

            if (trade.status === 'BUY_ORDER_PLACED') {
                const orderStatus = await checkOrderStatus(apiKey, secretKey, trade.symbol, trade.buyOrderId, trade.useTestnet);

                if (orderStatus.status === 'FILLED') {
                    const fillPrice = parseFloat(orderStatus.price);
                    const filledQuantity = parseFloat(orderStatus.executedQty);
                    const sellPrice = fillPrice * (1 + trade.profitPercent / 100);

                    const sellOrder = await placeLimitOrder(apiKey, secretKey, trade.symbol, 'SELL', filledQuantity, sellPrice, trade.useTestnet);

                    trade.status = 'SELL_ORDER_PLACED';
                    trade.sellOrderId = sellOrder.orderId;
                    trade.sellPrice = sellPrice;
                    trade.entryPrice = fillPrice;
                    trade.filledQuantity = filledQuantity;

                    console.log(`✅ BUY ORDER FILLED: ${filledQuantity} ${trade.symbol} at ${fillPrice} USDT`);
                }
            } else if (trade.status === 'SELL_ORDER_PLACED') {
                const orderStatus = await checkOrderStatus(apiKey, secretKey, trade.symbol, trade.sellOrderId, trade.useTestnet);

                if (orderStatus.status === 'FILLED') {
                    const fillPrice = parseFloat(orderStatus.price);
                    const profit = (fillPrice - trade.entryPrice) * trade.filledQuantity;
                    const profitPercent = (profit / trade.investmentAmount) * 100;

                    // Save to trade history
                    const userTradeFile = path.join(TRADES_DIR, trade.userId.replace(/[^a-z0-9]/gi, '_') + '.json');
                    let history = [];
                    if (fs.existsSync(userTradeFile)) {
                        history = JSON.parse(fs.readFileSync(userTradeFile));
                    }
                    history.unshift({
                        symbol: trade.symbol,
                        entryPrice: trade.entryPrice,
                        exitPrice: fillPrice,
                        quantity: trade.filledQuantity,
                        investment: trade.investmentAmount,
                        profit: profit,
                        profitPercent: profitPercent,
                        timestamp: new Date().toISOString()
                    });
                    fs.writeFileSync(userTradeFile, JSON.stringify(history, null, 2));

                    activeTradingSessions.delete(sessionId);
                    console.log(`✅ TRADE COMPLETED: Profit $${profit.toFixed(2)} (${profitPercent.toFixed(2)}%) for ${trade.userId}`);
                }
            }

            // Check time limit
            if (Date.now() - trade.startTime > trade.timeLimitHours * 60 * 60 * 1000) {
                if (trade.buyOrderId && trade.status === 'BUY_ORDER_PLACED') {
                    await cancelOrder(apiKey, secretKey, trade.symbol, trade.buyOrderId, trade.useTestnet);
                }
                if (trade.sellOrderId && trade.status === 'SELL_ORDER_PLACED') {
                    await cancelOrder(apiKey, secretKey, trade.symbol, trade.sellOrderId, trade.useTestnet);
                }
                activeTradingSessions.delete(sessionId);
                console.log(`⏰ Session ${sessionId} expired for ${trade.userId}`);
            }

        } catch (error) {
            console.error(`Order check error for ${sessionId}:`, error.message);
        }
    }
}, 30000); // Check every 30 seconds

// ==================== TRADE HISTORY ====================
app.get('/api/trade-history', authenticate, (req, res) => {
    const userFile = path.join(TRADES_DIR, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
    if (!fs.existsSync(userFile)) {
        return res.json({ success: true, trades: [] });
    }
    const trades = JSON.parse(fs.readFileSync(userFile));
    res.json({ success: true, trades: trades });
});

// ==================== HALAL ASSETS ====================
app.get('/api/halal-assets', authenticate, (req, res) => {
    res.json({
        success: true,
        assets: HALAL_ASSETS,
        count: HALAL_ASSETS.length,
        message: 'These assets are considered halal for spot trading'
    });
});

// ==================== ADMIN ENDPOINTS ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false, message: 'Admin only' });

    const pending = readPending();
    const list = Object.keys(pending).map(email => ({
        email: email,
        requestedAt: pending[email].requestedAt
    }));
    res.json({ success: true, pending: list });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });

    const { email } = req.body;
    const pending = readPending();

    if (!pending[email]) {
        return res.status(404).json({ success: false, message: 'User not found in pending requests' });
    }

    const users = readUsers();
    users[email] = {
        email: email,
        password: pending[email].password,
        isOwner: false,
        isApproved: true,
        isBlocked: false,
        apiKey: "",
        secretKey: "",
        createdAt: new Date().toISOString(),
        approvedAt: new Date().toISOString()
    };
    writeUsers(users);

    delete pending[email];
    writePending(pending);

    res.json({ success: true, message: `User ${email} has been approved` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });

    const { email } = req.body;
    const pending = readPending();

    if (!pending[email]) {
        return res.status(404).json({ success: false, message: 'User not found in pending requests' });
    }

    delete pending[email];
    writePending(pending);

    res.json({ success: true, message: `User ${email} has been rejected` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });

    const { email } = req.body;
    const users = readUsers();

    if (!users[email]) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);

    const status = users[email].isBlocked ? 'BLOCKED' : 'ACTIVE';
    res.json({ success: true, message: `User ${email} is now ${status}` });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });

    const users = readUsers();
    const list = Object.keys(users).map(email => ({
        email: email,
        hasApiKeys: !!users[email].apiKey,
        isOwner: users[email].isOwner,
        isApproved: users[email].isApproved,
        isBlocked: users[email].isBlocked,
        createdAt: users[email].createdAt,
        approvedAt: users[email].approvedAt || null
    }));

    res.json({ success: true, users: list });
});

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });

    const users = readUsers();
    const balances = {};

    for (const [email, userData] of Object.entries(users)) {
        if (!userData.apiKey) {
            balances[email] = {
                spot: 0,
                funding: 0,
                total: 0,
                hasKeys: false
            };
            continue;
        }

        try {
            const apiKey = decrypt(userData.apiKey);
            const secretKey = decrypt(userData.secretKey);
            const spotBalance = await getSpotBalance(apiKey, secretKey, false);
            const fundingBalance = await getFundingBalance(apiKey, secretKey, false);

            balances[email] = {
                spot: spotBalance,
                funding: fundingBalance,
                total: spotBalance + fundingBalance,
                hasKeys: true,
                lastUpdated: new Date().toISOString()
            };
        } catch (error) {
            balances[email] = {
                spot: 0,
                funding: 0,
                total: 0,
                hasKeys: true,
                error: error.message
            };
        }
    }

    res.json({ success: true, balances: balances });
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

// ==================== CHANGE PASSWORD ====================
app.post('/api/change-password', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });

    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];

    if (!bcrypt.compareSync(currentPassword, owner.password)) {
        return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }

    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ success: false, message: 'New password must be at least 6 characters' });
    }

    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);

    res.json({ success: true, message: 'Password changed successfully! Please login again.' });
});

// ==================== SERVE FRONTEND ====================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ==================== START SERVER ====================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`🕋 PURELY HALAL TRADING BOT`);
    console.log(`========================================`);
    console.log(`✅ Server: http://localhost:${PORT}`);
    console.log(`✅ Owner Email: mujtabahatif@gmail.com`);
    console.log(`✅ Owner Password: Mujtabah@2598`);
    console.log(`✅ ${HALAL_ASSETS.length} Halal Assets Available`);
    console.log(`✅ No Riba | No Gharar | No Maysir | No Leverage`);
    console.log(`✅ Real Binance API | Limit Orders Only`);
    console.log(`✅ Admin: Approve/Reject Users | Block/Unblock | View Balances | View All Trades`);
    console.log(`========================================\n`);
});
