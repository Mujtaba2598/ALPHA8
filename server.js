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

// ==================== HALAL ASSETS ====================
const HALAL_ASSETS = [
    'BTCUSDT', 'ETHUSDT', 'BNBUSDT', 'SOLUSDT', 'ADAUSDT', 
    'XRPUSDT', 'DOTUSDT', 'LINKUSDT', 'MATICUSDT', 'AVAXUSDT'
];

// ==================== CREATE DATA DIRECTORIES ====================
const DATA_DIR = path.join(__dirname, 'data');
const TRADES_DIR = path.join(DATA_DIR, 'trades');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PENDING_FILE = path.join(DATA_DIR, 'pending.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

// Create directories
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(TRADES_DIR)) fs.mkdirSync(TRADES_DIR, { recursive: true });

// ==================== CREATE OWNER ACCOUNT IF NOT EXISTS ====================
if (!fs.existsSync(USERS_FILE)) {
    const ownerPasswordHash = bcrypt.hashSync('Mujtabah@2598', 10);
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: ownerPasswordHash,
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
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
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return "";
    const [ivHex, encryptedHex] = text.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const encryptedText = Buffer.from(encryptedHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        message: '🕋 100% HALAL Trading Bot - No Riba, No Gharar, No Maysir',
        timestamp: new Date().toISOString()
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
    
    const users = readUsers();
    const user = users[email];
    
    if (!user) {
        const pending = readPending();
        if (pending[email]) {
            return res.status(401).json({ success: false, message: 'Pending approval' });
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
function cleanKey(key) {
    return key ? key.replace(/[\s\n\r\t]+/g, '').trim() : "";
}

async function binanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET', useDemo = false) {
    const baseUrl = useDemo ? 'https://testnet.binance.vision' : 'https://api.binance.com';
    const timestamp = Date.now();
    const queryString = Object.keys({ ...params, timestamp })
        .sort()
        .map(k => `${k}=${params[k] || timestamp}`)
        .join('&');
    
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

async function getRealBalance(apiKey, secretKey, useDemo = false) {
    try {
        const account = await binanceRequest(apiKey, secretKey, '/api/v3/account', {}, 'GET', useDemo);
        const usdtAsset = account.balances.find(b => b.asset === 'USDT');
        return parseFloat(usdtAsset?.free || 0);
    } catch (error) {
        return 0;
    }
}

async function getFundingBalance(apiKey, secretKey, useDemo = false) {
    try {
        const timestamp = Date.now();
        const queryString = `timestamp=${timestamp}`;
        const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');
        const baseUrl = useDemo ? 'https://testnet.binance.vision' : 'https://api.binance.com';
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

async function getRealPrice(symbol, useDemo = false) {
    const baseUrl = useDemo ? 'https://testnet.binance.vision' : 'https://api.binance.com';
    const response = await axios.get(`${baseUrl}/api/v3/ticker/price?symbol=${symbol}`);
    return parseFloat(response.data.price);
}

async function placeRealLimitOrder(apiKey, secretKey, symbol, side, quantity, price, useDemo = false) {
    const order = await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol,
        side,
        type: 'LIMIT',
        timeInForce: 'GTC',
        quantity: quantity.toFixed(6),
        price: price.toFixed(2)
    }, 'POST', useDemo);
    return order;
}

async function checkRealOrderStatus(apiKey, secretKey, symbol, orderId, useDemo = false) {
    const order = await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol,
        orderId
    }, 'GET', useDemo);
    return order;
}

async function cancelRealOrder(apiKey, secretKey, symbol, orderId, useDemo = false) {
    const result = await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol,
        orderId
    }, 'DELETE', useDemo);
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
    const useDemo = accountType === 'testnet';
    
    try {
        const spotBalance = await getRealBalance(cleanApi, cleanSecret, useDemo);
        const fundingBalance = await getFundingBalance(cleanApi, cleanSecret, useDemo);
        
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        
        res.json({ 
            success: true, 
            message: `API keys saved! Spot: ${spotBalance} USDT | Funding: ${fundingBalance} USDT`,
            spotBalance: spotBalance,
            fundingBalance: fundingBalance
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Invalid API keys. Check permissions.' });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const users = readUsers();
    const user = users[req.user.email];
    
    if (!user.apiKey) {
        return res.status(400).json({ success: false, message: 'No API keys saved' });
    }
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useDemo = accountType === 'testnet';
    
    try {
        const spotBalance = await getRealBalance(apiKey, secretKey, useDemo);
        const fundingBalance = await getFundingBalance(apiKey, secretKey, useDemo);
        
        res.json({ 
            success: true, 
            spotBalance: spotBalance,
            fundingBalance: fundingBalance,
            totalBalance: spotBalance + fundingBalance,
            message: `Connected! Spot: ${spotBalance} USDT | Funding: ${fundingBalance} USDT`
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Connection failed. Check API keys.' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user.apiKey) {
        return res.json({ success: false, message: 'No keys saved' });
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
        return res.json({ success: false, message: 'No API keys' });
    }
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useDemo = accountType === 'testnet';
    
    try {
        const spotBalance = await getRealBalance(apiKey, secretKey, useDemo);
        const fundingBalance = await getFundingBalance(apiKey, secretKey, useDemo);
        
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

// ==================== REAL TRADING ENGINE ====================
const activeTrades = new Map();
let assetIndex = 0;

function getNextAsset() {
    const asset = HALAL_ASSETS[assetIndex];
    assetIndex = (assetIndex + 1) % HALAL_ASSETS.length;
    return asset;
}

app.post('/api/start-trading', authenticate, async (req, res) => {
    const { investmentAmount, profitPercent, timeLimitHours, accountType } = req.body;
    
    if (investmentAmount < 10) {
        return res.status(400).json({ success: false, message: 'Minimum investment: $10' });
    }
    if (profitPercent < 0.1 || profitPercent > 5) {
        return res.status(400).json({ success: false, message: 'Profit target: 0.1% - 5%' });
    }
    if (timeLimitHours < 1 || timeLimitHours > 168) {
        return res.status(400).json({ success: false, message: 'Time limit: 1-168 hours' });
    }
    
    const users = readUsers();
    const user = users[req.user.email];
    if (!user.apiKey) {
        return res.status(400).json({ success: false, message: 'Add API keys first' });
    }
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useDemo = accountType === 'testnet';
    
    try {
        const spotBalance = await getRealBalance(apiKey, secretKey, useDemo);
        const fundingBalance = await getFundingBalance(apiKey, secretKey, useDemo);
        const totalBalance = spotBalance + fundingBalance;
        
        if (totalBalance < investmentAmount) {
            return res.status(400).json({ 
                success: false, 
                message: `Insufficient balance. You have ${totalBalance} USDT (Spot: ${spotBalance}, Funding: ${fundingBalance}), need ${investmentAmount}`
            });
        }
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Cannot verify balance. Check API keys.' });
    }
    
    const sessionId = crypto.randomBytes(16).toString('hex');
    const symbol = getNextAsset();
    const currentPrice = await getRealPrice(symbol, useDemo);
    const buyPrice = currentPrice * 0.998;
    const quantity = investmentAmount / buyPrice;
    
    try {
        const order = await placeRealLimitOrder(apiKey, secretKey, symbol, 'BUY', quantity, buyPrice, useDemo);
        
        activeTrades.set(sessionId, {
            userId: req.user.email,
            symbol,
            buyOrderId: order.orderId,
            buyPrice,
            quantity,
            investmentAmount,
            profitPercent,
            timeLimitHours,
            startTime: Date.now(),
            useDemo,
            status: 'BUY_ORDER_PLACED'
        });
        
        const orders = readOrders();
        orders[sessionId] = {
            userId: req.user.email,
            symbol,
            buyOrderId: order.orderId,
            buyPrice,
            quantity,
            investmentAmount,
            profitPercent,
            startTime: new Date().toISOString(),
            status: 'BUY_ORDER_PLACED'
        };
        writeOrders(orders);
        
        res.json({ 
            success: true, 
            sessionId,
            message: `✅ Halal buy order placed: ${quantity.toFixed(6)} ${symbol} @ ${buyPrice} USDT`
        });
        
    } catch (error) {
        res.status(500).json({ success: false, message: `Order failed: ${error.message}` });
    }
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    activeTrades.delete(sessionId);
    res.json({ success: true, message: 'Trading stopped' });
});

app.post('/api/trade-status', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const trade = activeTrades.get(sessionId);
    
    if (!trade) {
        return res.json({ success: true, active: false });
    }
    
    res.json({
        success: true,
        active: true,
        symbol: trade.symbol,
        buyPrice: trade.buyPrice,
        quantity: trade.quantity,
        status: trade.status,
        profitPercent: trade.profitPercent
    });
});

// Background order checker
setInterval(async () => {
    for (const [sessionId, trade] of activeTrades) {
        if (trade.status === 'BUY_ORDER_PLACED') {
            try {
                const users = readUsers();
                const user = users[trade.userId];
                if (!user || !user.apiKey) continue;
                
                const apiKey = decrypt(user.apiKey);
                const secretKey = decrypt(user.secretKey);
                
                const orderStatus = await checkRealOrderStatus(apiKey, secretKey, trade.symbol, trade.buyOrderId, trade.useDemo);
                
                if (orderStatus.status === 'FILLED') {
                    const fillPrice = parseFloat(orderStatus.price);
                    const sellPrice = fillPrice * (1 + trade.profitPercent / 100);
                    const sellOrder = await placeRealLimitOrder(apiKey, secretKey, trade.symbol, 'SELL', trade.quantity, sellPrice, trade.useDemo);
                    
                    trade.status = 'SELL_ORDER_PLACED';
                    trade.sellOrderId = sellOrder.orderId;
                    trade.sellPrice = sellPrice;
                    trade.entryPrice = fillPrice;
                }
            } catch (error) {
                console.error('Order check error:', error.message);
            }
        }
        
        if (trade.status === 'SELL_ORDER_PLACED') {
            try {
                const users = readUsers();
                const user = users[trade.userId];
                if (!user || !user.apiKey) continue;
                
                const apiKey = decrypt(user.apiKey);
                const secretKey = decrypt(user.secretKey);
                
                const orderStatus = await checkRealOrderStatus(apiKey, secretKey, trade.symbol, trade.sellOrderId, trade.useDemo);
                
                if (orderStatus.status === 'FILLED') {
                    const fillPrice = parseFloat(orderStatus.price);
                    const profit = (fillPrice - trade.entryPrice) * trade.quantity;
                    const profitPercent = (profit / trade.investmentAmount) * 100;
                    
                    const userFile = path.join(TRADES_DIR, trade.userId.replace(/[^a-z0-9]/gi, '_') + '.json');
                    let history = [];
                    if (fs.existsSync(userFile)) {
                        history = JSON.parse(fs.readFileSync(userFile));
                    }
                    history.unshift({
                        symbol: trade.symbol,
                        entryPrice: trade.entryPrice,
                        exitPrice: fillPrice,
                        quantity: trade.quantity,
                        profit: profit,
                        profitPercent: profitPercent,
                        timestamp: new Date().toISOString()
                    });
                    fs.writeFileSync(userFile, JSON.stringify(history, null, 2));
                    
                    activeTrades.delete(sessionId);
                }
            } catch (error) {
                console.error('Sell order error:', error.message);
            }
        }
        
        if (Date.now() - trade.startTime > trade.timeLimitHours * 60 * 60 * 1000) {
            activeTrades.delete(sessionId);
        }
    }
}, 30000);

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
    res.json({ success: true, assets: HALAL_ASSETS });
});

// ==================== ADMIN ENDPOINTS ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false, message: 'Admin only' });
    const pending = readPending();
    res.json({ success: true, pending: Object.keys(pending).map(email => ({ email, ...pending[email] })) });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    
    if (!pending[email]) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const users = readUsers();
    users[email] = {
        email,
        password: pending[email].password,
        isOwner: false,
        isApproved: true,
        isBlocked: false,
        apiKey: "",
        secretKey: "",
        createdAt: new Date().toISOString()
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    
    res.json({ success: true, message: `User ${email} approved` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} rejected` });
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
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'BLOCKED' : 'ACTIVE'}` });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({
        email,
        hasApiKeys: !!users[email].apiKey,
        isOwner: users[email].isOwner,
        isApproved: users[email].isApproved,
        isBlocked: users[email].isBlocked,
        createdAt: users[email].createdAt
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const users = readUsers();
    const balances = {};
    
    for (const [email, userData] of Object.entries(users)) {
        if (!userData.apiKey) {
            balances[email] = { spot: 0, funding: 0, total: 0, hasKeys: false };
            continue;
        }
        
        try {
            const apiKey = decrypt(userData.apiKey);
            const secretKey = decrypt(userData.secretKey);
            const spotBalance = await getRealBalance(apiKey, secretKey, false);
            const fundingBalance = await getFundingBalance(apiKey, secretKey, false);
            
            balances[email] = {
                spot: spotBalance,
                funding: fundingBalance,
                total: spotBalance + fundingBalance,
                hasKeys: true,
                lastUpdated: new Date().toISOString()
            };
        } catch (error) {
            balances[email] = { spot: 0, funding: 0, total: 0, hasKeys: true, error: error.message };
        }
    }
    
    res.json({ success: true, balances });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const allTrades = {};
    const files = fs.readdirSync(TRADES_DIR);
    for (const file of files) {
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
    
    if (!bcrypt.compareSync(currentPassword, owner.password)) {
        return res.status(401).json({ success: false, message: 'Current password incorrect' });
    }
    
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed successfully' });
});

// ==================== SERVE FRONTEND ====================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ==================== START SERVER ====================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🕋 100% HALAL TRADING BOT`);
    console.log(`========================================`);
    console.log(`✅ Owner: mujtabahatif@gmail.com`);
    console.log(`✅ Password: Mujtabah@2598`);
    console.log(`✅ ${HALAL_ASSETS.length} Halal Assets`);
    console.log(`✅ No Riba | No Gharar | No Maysir | No Leverage`);
    console.log(`✅ Real Binance API - No Simulation`);
    console.log(`✅ Admin: Block/Unblock Users | View Balances | View All Trades`);
    console.log(`========================================`);
    console.log(`Server running on port: ${PORT}`);
});
