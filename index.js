const express = require("express");
const moment = require("moment");
const path = require("path");
const fs = require('fs')
const TelegramBot = require('node-telegram-bot-api');
const config = require("./config");

const bot = new TelegramBot(config.token, {
    polling: true,
    parse_mode: 'HTML',
    allowedUpdates: ['message', 'callback_query', 'inline_query', 'channel_post', 'edited_message']
});

bot.on('error', (error) => {
    console.error('Telegram Bot Error:', error.message);
});

bot.on('polling_error', (error) => {
    console.error('Polling Error:', error.message);
});

const commands = new Map();
const commandsPath = path.join(__dirname, 'script', 'commands');

const events = new Map();

const eventsPath = path.join(__dirname, "script", "events");


if (!fs.existsSync(commandsPath)) {
    fs.mkdirSync(commandsPath);
}

fs.readdirSync(commandsPath).forEach((file) => {
    if (file.endsWith(".js")) {
        try {
            const command = require(path.join(commandsPath, file));
            const eurix = command.eurix;

            if (!eurix.name || !command.execute) {
                console.error(`Invalid command file: ${file}`);
                return;
            }

            commands.set(eurix.name, command);
            global.commands = commands;
        } catch (error) {
            console.error(`Error loading command file: ${file} ${error.message}`);
        }
    }
});

try {
    if (!fs.existsSync(eventsPath)) {
        fs.mkdirSync(eventsPath, { recursive: true });
    }

    fs.readdirSync(eventsPath).forEach((file) => {
        if (file.endsWith(".js")) {
            try {
                const eventPath = path.join(eventsPath, file);
                delete require.cache[require.resolve(eventPath)];
                const event = require(eventPath);

                if (!event || !event.name || typeof event.execute !== 'function') {
                    console.error(`Invalid event structure in file: ${file}`);
                    return;
                }

                events.set(event.name, event);
            } catch (error) {
                console.error(`Error loading event file ${file}:`, error.message);
            }
        }
    });
} catch (error) {
    console.error("Error loading events directory:", error);
}

                events.forEach((event) => {
                    switch(event.name) {
                        case 'welcome':
                            bot.on('new_chat_members', async (msg) => {
                                try {
                                    await event.execute(bot, msg);
                                } catch (error) {
                                    console.error(`Error executing welcome event: ${error.message}`);
                                }
                            });
                            break;
                        case 'leave':
                            bot.on('left_chat_member', async (msg) => {
                                try {
                                    await event.execute(bot, msg);
                                } catch (error) {
                                    console.error(`Error executing leave event: ${error.message}`);
                                }
                            });
                            break;
                        case 'feedback':
                            // Register to capture all messages with videos or photos
                            bot.on('message', async (msg) => {
                                if (msg.video || (msg.photo && msg.photo.length > 0)) {
                                    try {
                                        await event.execute(bot, msg);
                                    } catch (error) {
                                        console.error(`Error executing feedback event: ${error.message}`);
                                    }
                                }
                            });
                            break;
                    }
                    console.log(`Loaded event: ${event.name}`);
                });

// Permission checking function
function hasPermission(userId, requiredPermission) {
    if (!requiredPermission || requiredPermission === 'all') return true;
    if (requiredPermission === 'admin') {
        return config.admin.includes(userId.toString());
    }
    return false;
}

// Store a reference to active feedback sessions
let feedbackSessions = new Map();

bot.on('message', async (msg) => {
    // Check if this is part of an ongoing feedback session
    if (msg.from && feedbackSessions.has(msg.from.id)) {
        // If it's a command to cancel, let the feedback command handle it
        if (msg.text && msg.text.startsWith('/') && msg.text !== '/cancel') {
            // Allow commands to pass through
        } 
        // Otherwise, forward to the feedback command
        else {
            try {
                const feedbackCommand = commands.get('feedback');
                if (feedbackCommand) {
                    await feedbackCommand.execute(bot, msg, []);
                    return;
                }
            } catch (error) {
                console.error('Error handling feedback session:', error);
            }
        }
    }

    if (!msg.text || !msg.text.startsWith('/')) return;

    let commandText = msg.text.split('@')[0];
    const args = commandText.slice(1).trim().split(/ +/);
    const commandName = args.shift().toLowerCase();

    if (!commands.has(commandName)) return;

    try {
        const command = commands.get(commandName);
        const permission = command.eurix.permission || 'all';

        if (!hasPermission(msg.from.id, permission)) {
            return bot.sendMessage(msg.chat.id, '❌ You do not have permission to use this command.');
        }

        // If this is a feedback command, register the session
        if (commandName === 'feedback' && msg.from) {
            if (command.feedbackSessions) {
                // Use the command's internal map if available
                feedbackSessions = command.feedbackSessions;
            }
        }

        await command.execute(bot, msg, args);
    } catch (error) {
        console.error(`Error executing command ${commandName}:`, error);
        await bot.sendMessage(msg.chat.id, '❌ An error occurred while executing the command.');
    }
});

const adminChatIds = config.admin;
const bcrypt = require("bcryptjs");
const multer = require("multer");

const USERPANEL_DIR = path.join(__dirname, "USERPANEL");
const profilePicturesDir = path.join(USERPANEL_DIR, 'profile_pictures');

try {
    if (!fs.existsSync(USERPANEL_DIR)) {
        fs.mkdirSync(USERPANEL_DIR, { recursive: true });
    }
    if (!fs.existsSync(profilePicturesDir)) {
        fs.mkdirSync(profilePicturesDir, { recursive: true });
    }

    // Create users.json if it doesn't exist
    const usersFilePath = path.join(USERPANEL_DIR, 'users.json');
    if (!fs.existsSync(usersFilePath)) {
        fs.writeFileSync(usersFilePath, '{}', 'utf8');
    }
} catch (error) {
    console.error("Error creating directories:", error);
}


// Configure multer with error handling

// Create uploads directory if it doesn't exist


const upload = multer({
    storage: multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, "./");
        },
        filename: function (req, file, cb) {
            cb(null, Date.now() + '-' + file.originalname);
        }
    }),
    fileFilter: function (req, file, cb) {
        if (file.mimetype.startsWith('image/') || file.originalname.endsWith('.lua')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files or .lua files are allowed'), false);
        }
    }
});


const axios = require("axios");
const jwt = require("jsonwebtoken");
const ping = require("ping");

const app = express();
app.use(express.json());
app.use('/profile_pictures', express.static(profilePicturesDir));

app.get('/user-profile', authenticateToken, async function (req, res) {
    try {
        const username = req.user.username;
        const targetUsername = req.query.username || username;
        const usersFilePath = path.join(USERPANEL_DIR, 'users.json');
        const userDir = path.join(profilePicturesDir, targetUsername);

        let users = {};
        if (fs.existsSync(usersFilePath)) {
            users = JSON.parse(fs.readFileSync(usersFilePath, 'utf8'));
        }

        let profilePicture = users[targetUsername]?.profilePicture || null;

        if (!profilePicture && fs.existsSync(userDir)) {
            const files = fs.readdirSync(userDir);
            const profilePic = files.find(file => file.startsWith('profile'));
            if (profilePic) {
                profilePicture = `/profile_pictures/${targetUsername}/${profilePic}?t=${Date.now()}`;
            }
        }

        res.json({
            profilePicture: profilePicture,
            username: targetUsername,
            isOwnProfile: username === targetUsername
        });
    } catch (error) {
        console.error('Error getting profile:', error);
        res.status(500).json({ error: 'Failed to get profile information' });
    }
});

app.get('/user-list', authenticateToken, (req, res) => {
    try {
        res.json([req.user.username]);
    } catch (error) {
        console.error('Error getting user list:', error);
        res.status(500).json({ error: 'Failed to get user list' });
    }
});


const PORT = 3000;
const SECRET_KEY = process.env.SECRET_KEY || "EugenePogi";

const USER_IP_FILE = path.join(__dirname, "UserIp.json");
const LOGIN_USER_FILE = path.join(__dirname, "LoginUser.json");

let keysCache = {};

// Function to load keys from file
function loadKeys(username) {
    const keyFilePath = path.join(USERPANEL_DIR, `${username}.json`);
    if (fs.existsSync(keyFilePath)) {
        try {
            keysCache = JSON.parse(fs.readFileSync(keyFilePath, "utf8"));
        } catch (error) {
            console.error("Error loading keys:", error.message);
            keysCache = {};
        }
    } else {
        keysCache = {};
        saveKeys(username);
    }
}

function saveKeys(username) {
    const keyFilePath = path.join(USERPANEL_DIR, `${username}.json`);
    fs.writeFileSync(keyFilePath, JSON.stringify(keysCache, null, 2), "utf8");
}

function isValidKey(apiKey) {
    if (!keysCache[apiKey]) return false;
    if (!keysCache[apiKey].zipCode || !keysCache[apiKey].deviceLimit) return false;
    return moment().isBefore(moment(keysCache[apiKey].expirationDate, "YYYY-MM-DD"));
}

function cleanupExpiredKeys(username) {
    const now = moment();
    let hasExpired = false;
    Object.keys(keysCache).forEach((key) => {
        if (moment(keysCache[key].expirationDate, "YYYY-MM-DD").isBefore(now)) {
            delete keysCache[key];
            hasExpired = true;
            console.log(`Deleted expired key: ${key}`);
        }
    });
    if (hasExpired) {
        saveKeys(username);
    }
    return hasExpired;
}

function authenticateToken(req, res, next) {
    try {
        const token = req.headers.authorization;
        if (!token) {
            return res.status(401).json({ error: "Access denied. Token required." });
        }

        jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err) {
                return res.status(403).json({ error: "Invalid or expired token" });
            }

            const userIp = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
            const username = decoded.username;

            // Verify user exists
            const users = JSON.parse(fs.readFileSync(LOGIN_USER_FILE, "utf8"));
            if (!users[username]) {
                return res.status(403).json({ error: "User not found" });
            }

            // Load IP data
            const ipData = JSON.parse(fs.readFileSync(USER_IP_FILE, "utf8"));
            const userIpData = ipData.find(entry => entry.query === userIp);

            if (!userIpData) {
                logUserIp(req); // Log new IP
            }

            req.user = { username, ip: userIp };
            loadKeys(username);
            next();
        });
    } catch (error) {
        console.error("Authentication error:", error);
        return res.status(500).json({ error: "Authentication failed" });
    }
}

async function logUserIp(req) {
    const userIp = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
    let ipData = [];

    try {
        if (fs.existsSync(USER_IP_FILE)) {
            const fileContent = fs.readFileSync(USER_IP_FILE, "utf8");
            if (fileContent) {
                ipData = JSON.parse(fileContent);
            }
        }
    } catch (error) {
        console.error("Error reading IP log file:", error.message);
        // Create empty file if doesn't exist
        fs.writeFileSync(USER_IP_FILE, "[]", "utf8");
    }

    const existingEntry = ipData.find(entry => entry.query === userIp); 
    if (existingEntry) {
        const lastLogTime = moment(existingEntry.time, "YYYY-MM-DD HH:mm:ss");
        if (moment().diff(lastLogTime, "hours") < 1) {
            return; 
        }
    }

    try {
        const data = await axios.get(`http://ip-api.com/json/${userIp}`);

        const ipInfo = {
            status: data.data.status,
            country: data.data.country || "Unknown",
            countryCode: data.data.countryCode || "Unknown",
            region: data.data.region || "Unknown",
            regionName: data.data.regionName || "Unknown",
            city: data.data.city || "Unknown",
            zip: data.data.zip || "Unknown",
            lat: data.data.lat || 0,
            lon: data.data.lon || 0,
            timezone: data.data.timezone || "Unknown",
            isp: data.data.isp || "Unknown",
            org: data.data.org || "Unknown",
            as: data.data.as || "Unknown",
            query: data.data.query || userIp, 
            time: moment().format("YYYY-MM-DD HH:mm:ss"),
        };

        // Remove old entry if IP already exists
        ipData = ipData.filter(entry => entry.query !== userIp);

        ipData.push(ipInfo);


        fs.writeFileSync(USER_IP_FILE, JSON.stringify(ipData, null, 2), "utf8");
    } catch (error) {
        console.error("IP lookup failed:", error.message);
    }
}

app.use(async (req, res, next) => {
    await logUserIp(req);
    next();
});

app.get("/get-ip-list", async function (req, res) {
res.sendFile(path.join(__dirname, "UserIp.json"));
});

app.get("/ip", (req, res) => {
res.sendFile(path.join(__dirname, "USERIP.html"));
    });

app.get("/shoti", async function (req, res) {
    try {
        const response = await axios.get("https://betadash-shoti-yazky.vercel.app/shotizxx?apikey=shipazu");
        if (!response.data || !response.data.shotiurl) {
            return res.status(500).json({ error: "Invalid response from Shoti API" });
        }
        res.json(response.data);
    } catch (error) {
        console.error("Shoti API Error:", error.message);
        return res.status(500).json({ error: "Failed to fetch from Shoti API" });
    }
});

app.get("/key", authenticateToken, (req, res) => {
    const keyFilePath = path.join(USERPANEL_DIR, `${req.user.username}.json`);
    if (!fs.existsSync(keyFilePath)) {
        return res.status(404).json({ error: "No API keys found for this user" });
    }
    loadKeys(req.user.username);
    cleanupExpiredKeys(req.user.username);
    res.sendFile(keyFilePath);
});

app.get("/", async (req, res) => {
    res.sendFile(path.join(__dirname, "genapikey.html"));
});

app.post("/signup", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: "Username and password are required" });
        }

        if (!fs.existsSync(LOGIN_USER_FILE)) {
            fs.writeFileSync(LOGIN_USER_FILE, '{}', 'utf8');
        }

        let users = JSON.parse(fs.readFileSync(LOGIN_USER_FILE, "utf8"));

        if (users[username]) {
            return res.status(400).json({ error: "Username already exists" });
        }

        const token = await bcrypt.hash(password, 10);
        const registrationDate = new Date().toISOString().split('T')[0];

        users[username] = {
            token,
            password: password,
            registrationDate
        };

        await fs.promises.writeFile(LOGIN_USER_FILE, JSON.stringify(users, null, 2), "utf8");
        res.json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Signup error:", error);
        res.status(500).json({ error: "Failed to create account" });
    }
});

// Route: Login
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password are required" });

    if (!fs.existsSync(LOGIN_USER_FILE)) return res.status(400).json({ error: "User not found" });

    const users = JSON.parse(fs.readFileSync(LOGIN_USER_FILE, "utf8"));

    if (!users[username]) return res.status(400).json({ error: "Invalid username or password" });

    const isMatch = await bcrypt.compare(password, users[username].token);
    if (!isMatch) return res.status(400).json({ error: "Invalid username or password" });

    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });

    loadKeys(username); // Load user's keys after login

    res.json({ message: "Login successful", token });
});

app.post("/forgot-password", async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Username is required" });

    if (!fs.existsSync(LOGIN_USER_FILE)) return res.status(400).json({ error: "User not found" });

    let users = JSON.parse(fs.readFileSync(LOGIN_USER_FILE, "utf8"));

    if (!users[username]) return res.status(400).json({ error: "User not found" });

    const resetToken = jwt.sign({ username }, SECRET_KEY, { expiresIn: "15m" });

    users[username].resetToken = resetToken;
    fs.writeFileSync(LOGIN_USER_FILE, JSON.stringify(users, null, 2), "utf8");

    res.json({ message: "Password reset token generated", resetToken });
});

app.post("/reset-password", async (req, res) => {
    const { username, resetToken, newPassword } = req.body;
    if (!username || !resetToken || !newPassword) {
        return res.status(400).json({ error: "Username, reset token, and new password are required" });
    }

    if (!fs.existsSync(LOGIN_USER_FILE)) return res.status(400).json({ error: "User not found" });

    let users = JSON.parse(fs.readFileSync(LOGIN_USER_FILE, "utf8"));

    if (!users[username]) {
        return res.status(400).json({ error: "User not found" });
    }

    try {
        jwt.verify(resetToken, SECRET_KEY);
        if (users[username].resetToken !== resetToken) {
            return res.status(400).json({ error: "Invalid reset token" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        users[username].token = hashedPassword;
    } catch (error) {
        return res.status(400).json({ error: "Invalid or expired token" });
    }
    users[username].password = newPassword;  // Update the stored password
    delete users[username].resetToken;

    fs.writeFileSync(LOGIN_USER_FILE, JSON.stringify(users, null, 2), "utf8");

    res.json({ message: "Password reset successfully" });
});



// Route: Add API Key (Protected)
app.post("/add-key", authenticateToken, (req, res) => {
    const { apiKey, expirationDate, zipCode, type } = req.body;
    if (!apiKey || !moment(expirationDate, "YYYY-MM-DD", true).isValid()) {
        return res.status(400).json({ error: "Invalid API key or expiration date format" });
    }

    const keyType = type || '1 Key 1 Dev';

    if (keyType === '1 Key 1 Dev' && !zipCode) {
        return res.status(400).json({ error: "ZIP code is required for 1 Key 1 Dev" });
    }

    if (keysCache[apiKey]) {
        return res.status(400).json({ error: "This API key already exists" });
    }

    keysCache[apiKey] = {
        expirationDate,
        zipCode: keyType === '1 Key 1 Dev' ? zipCode : null,
        maintenance: false,
        type: keyType,
    };
    saveKeys(req.user.username);
    res.json({ message: "API key updated successfully", apiKey, expirationDate, zipCode });
});

// Route: Remove API Key (Protected)
app.post("/removekey", authenticateToken, (req, res) => {
    const { apiKey } = req.body;
    if (!keysCache[apiKey]) {
        return res.status(404).json({ message: "API Key not found!" });
    }

    delete keysCache[apiKey];
    saveKeys(req.user.username);
    res.json({ message: "API Key removed successfully!" });
});


let isMaintenanceMode = false;

app.get("/toggle-maintenance", authenticateToken, (req, res) => {
    isMaintenanceMode = !isMaintenanceMode;
    res.json({ 
        success: true, 
        maintenance: isMaintenanceMode, 
        message: isMaintenanceMode ? "Maintenance mode enabled" : "Maintenance mode disabled" 
    });
});

app.get("/execute", async (req, res) => {
    try {
        const userIp = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
        const { username, apiKey } = req.query;

        if (!username || !apiKey) {
            return res.status(400).json({ error: "Username and API key are required" });
        }

        const users = JSON.parse(fs.readFileSync(LOGIN_USER_FILE, "utf8"));
        if (!users[username]) {
            return res.status(404).json({ error: "User not found" });
        }

        // Load IP data
        let ipData = null;
        try {
            const ipDataRaw = fs.readFileSync(USER_IP_FILE, "utf8");
            const allIpData = JSON.parse(ipDataRaw);
            ipData = allIpData.find(entry => entry.query === userIp);
        } catch (error) {
            console.error("Error reading IP data:", error);
        }

        const notificationMsg = `⚡ IP Access Detected!\n\n` +
            `🌐 IP: ${userIp}\n` +
            `📍 Location: ${ipData?.city || 'Unknown'}, ${ipData?.country || 'Unknown'}\n` +
            `🏢 ISP: ${ipData?.isp || 'Unknown'}\n` +
            `📮 ZIP: ${ipData?.zip || 'Unknown'}\n` +
            `⏰ Time: ${moment().format("YYYY-MM-DD HH:mm:ss")}\n` +
            `🌍 Region: ${ipData?.regionName || 'Unknown'}\n` +
            `✅ Execution: Success\n` +
            `👤 Username: ${username}\n` +
            `🔑 API Key: ${apiKey}\n` +
            `🕒 Last Access: ${moment().format("YYYY-MM-DD HH:mm:ss")}\n` +
            `📊 Key Status: ${keysCache[apiKey] ? 'Active' : 'Invalid'}\n` +
            `📅 Key Expiration: ${keysCache[apiKey]?.expirationDate || 'Unknown'}\n` +
            `📊 Type: ${keysCache[apiKey]?.type || 'Unknown'}\n` +
            `✨ Status: Success`;

        adminChatIds.forEach(chatId => {
            bot.sendMessage(chatId, notificationMsg);
        });
        if (isMaintenanceMode || (keysCache[apiKey] && keysCache[apiKey].maintenance)) {
            return res.json({ error: "Your key is maintenance please contact the owner" });
        }

        if (!username || !apiKey) {
            return res.status(400).json({ error: "API key and username are required" });
        }

        // Get user's zip code from UserIp.json
        let zipInfo = "Unknown";
        try {
            if (fs.existsSync(USER_IP_FILE)) {
                const ipData = JSON.parse(fs.readFileSync(USER_IP_FILE, "utf8"));
                const userIpData = ipData.find(entry => entry.query === userIp);
                if (userIpData && userIpData.zip) {
                    zipInfo = userIpData.zip;
                }
            }
        } catch (error) {
            console.error("Error reading zip code:", error);
        }

        let zipCode = "Unknown";
        if (fs.existsSync(USER_IP_FILE)) {
            const ipData = JSON.parse(fs.readFileSync(USER_IP_FILE, "utf8") || "[]");
            const userIpData = ipData.find(entry => entry.query === userIp);
            if (userIpData && userIpData.zip) {
                zipCode = userIpData.zip;
            }
        }
        loadKeys(username);
        cleanupExpiredKeys(username);

        if (!keysCache[apiKey]) {
            // Send notification for wrong key attempt
            const wrongKeyMsg = `❌ Wrong Key Attempt!\n\n` +
                `🌐 IP: ${userIp}\n` +
                `📍 Location: ${ipData?.city || 'Unknown'}, ${ipData?.country || 'Unknown'}\n` +
                `🏢 ISP: ${ipData?.isp || 'Unknown'}\n` +
                `📮 ZIP: ${ipData?.zip || 'Unknown'}\n` +
                `⏰ Time: ${moment().format("YYYY-MM-DD HH:mm:ss")}\n` +
                `🌍 Region: ${ipData?.regionName || 'Unknown'}\n` +
                `❌ Execution: Failed\n` +
                `👤 Username: ${username}\n` +
                `🔑 Wrong API Key: ${apiKey}\n` +
                `⚠️ Status: Invalid Key`;

            adminChatIds.forEach(chatId => {
                bot.sendMessage(chatId, wrongKeyMsg);
            });

            return res.status(404).json({ error: "Wrong Key Plls contact the owner: @ZenoOnTop" });
        }

        const keyData = keysCache[apiKey];
        if (!keyData || !keyData.expirationDate) {
            return res.status(403).json({ error: "Invalid key data" });
        }

        if (moment().isAfter(moment(keyData.expirationDate, "YYYY-MM-DD"))) {
            return res.status(403).json({ error: "You need to buy a key again. Contact the owner: @ZenoOnTop" });
        }


        if (keysCache[apiKey].type === '1 Key 1 Dev') {
            if (!zipCode || !keysCache[apiKey].zipCode) {
                return res.status(403).json({ error: "ZIP code required for 1 Key 1 Dev" });
            }
            if (keysCache[apiKey].zipCode !== zipCode) {
                return res.status(403).json({ error: "Key registered to different ZIP code than your IP address" });
            }
        }

        const currentDate = moment();
            const expirationDate = moment(keyData.expirationDate);
            const remainingDays = expirationDate.diff(currentDate, "days");


            const deviceLimit = keysCache[apiKey].deviceLimit || 'unlimited';
            res.json({ 
                message: `Script is valid. Expires on: ${keysCache[apiKey].expirationDate}`, "Remaining Days": remainingDays,
                zipCode: zipInfo,
                type: keysCache[apiKey]?.type || '1 Key 1 Dev',
        status: "Success" });

    } catch (error) {
        res.status(500).json({ error: "An internal error occurred", details: error.message });
    }
});


app.get("/execute/lua", async function (req, res) {
    res.setHeader('Content-Disposition', 'attachment; filename=execute.lua');
    res.setHeader('Content-Type', 'application/x-lua');
    res.sendFile(path.join(__dirname, "execute.lua"));
});

app.get("/codm-uploader", (req, res) => {
    res.sendFile(path.join(__dirname, "codm_uploader.html"));
});

app.post("/upload-codm-script", upload.single('script'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
    }

    if (!req.file.originalname.endsWith('.lua')) {
        if (fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        return res.status(400).json({ message: "Only .lua files are allowed" });
    }

    try {
        // Basic server-side Lua validation
        const fileContent = fs.readFileSync(req.file.path, 'utf8');
        
        // Function to validate Lua file content
        function validateLuaFile(content) {
            const warnings = [];
            
            // Check for unbalanced parentheses
            let openParens = 0;
            for (let i = 0; i < content.length; i++) {
                if (content[i] === '(') openParens++;
                if (content[i] === ')') openParens--;
            }
            if (openParens !== 0) warnings.push("Unbalanced parentheses detected");
            
            // Check for unbalanced curly braces
            let openBraces = 0;
            for (let i = 0; i < content.length; i++) {
                if (content[i] === '{') openBraces++;
                if (content[i] === '}') openBraces--;
            }
            if (openBraces !== 0) warnings.push("Unbalanced curly braces detected");
            
            // Check for unclosed strings
            let inString = false;
            let stringDelimiter = '';
            for (let i = 0; i < content.length; i++) {
                const char = content[i];
                if (!inString && (char === '"' || char === "'")) {
                    inString = true;
                    stringDelimiter = char;
                } else if (inString && char === stringDelimiter && content[i-1] !== '\\') {
                    inString = false;
                }
            }
            if (inString) warnings.push("Unclosed string detected");
            
            // Check if the file contains basic Lua keywords
            const containsLuaKeywords = /\b(function|end|local|if|then|else|for|while|do|return)\b/.test(content);
            if (!containsLuaKeywords) {
                warnings.push("File doesn't appear to contain Lua code");
            }
            
            return { warnings };
        }
        
        const validationResult = validateLuaFile(fileContent);
        
        const targetPath = path.join(__dirname, "ZenoOnTopVip.lua");
        fs.copyFileSync(req.file.path, targetPath);
        fs.unlinkSync(req.file.path); // Clean up the temporary file

        // Notify admins via Telegram
        const notificationMsg = `📤 New CODM Script Uploaded!\n\n` +
            `📁 File: ${req.file.originalname}\n` +
            `📦 Size: ${(req.file.size / 1024).toFixed(2)} KB\n` +
            `⏰ Time: ${moment().format("YYYY-MM-DD HH:mm:ss")}` +
            (validationResult.warnings.length > 0 ? 
                `\n\n⚠️ Warnings:\n${validationResult.warnings.join('\n')}` : ``);

        adminChatIds.forEach(chatId => {
            bot.sendMessage(chatId, notificationMsg);
        });

        res.json({ 
            message: "Script uploaded successfully", 
            warnings: validationResult.warnings 
        });
    } catch (error) {
        console.error("Upload error:", error);
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ message: "Upload failed: " + error.message });
    }
});



app.get("/tuts", async function (req, res) {
    res.sendFile(path.join(__dirname, "Tuts", "tuts.mp4"));
});

app.get("/execute/info", function (req, res) {
    const userIp = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;

    try {
        if (fs.existsSync(USER_IP_FILE)) {
            const ipData = JSON.parse(fs.readFileSync(USER_IP_FILE, "utf8"));
            const userIpData = ipData.find(entry => entry.query === userIp);
            if (userIpData) {
                res.json([userIpData]);
            } else {
                res.json([{ zip: "Unknown", query: userIp }]);
            }
        } else {
            res.json([{ zip: "Unknown", query: userIp }]);
        }
    } catch (error) {
        console.error("Error retrieving IP data:", error);
        res.status(500).json([{ error: "Error retrieving IP data", zip: "Unknown" }]);
    }
});




// Start Server
app.post('/upload-profile-picture', authenticateToken, upload.single('profilePicture'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const username = req.user.username;
        const userProfileDir = path.join(profilePicturesDir, username);
        const usersFilePath = path.join(USERPANEL_DIR, 'users.json');

        // Ensure profile directories exist
        if (!fs.existsSync(profilePicturesDir)) {
            fs.mkdirSync(profilePicturesDir, { recursive: true });
        }
        
        if (!fs.existsSync(userProfileDir)) {
            fs.mkdirSync(userProfileDir, { recursive: true });
        }

        const fileExtension = path.extname(req.file.originalname).toLowerCase();
        if (!fileExtension.match(/\.(jpg|jpeg|png|gif)$/i)) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Invalid file type. Please upload an image file.' });
        }

        // Remove old profile pictures
        try {
            const oldFiles = fs.readdirSync(userProfileDir);
            for (const file of oldFiles) {
                if (file.startsWith('profile')) {
                    fs.unlinkSync(path.join(userProfileDir, file));
                }
            }
        } catch (err) {
            console.error('Error cleaning old files:', err);
        }

        const profilePicPath = path.join(userProfileDir, `profile${fileExtension}`);

        try {
            // Use copyFile instead of rename to avoid issues across different file systems
            fs.copyFileSync(req.file.path, profilePicPath);
            fs.unlinkSync(req.file.path); // Clean up the temp file after copying

            // Update users.json with profile picture info
            let users = {};
            if (fs.existsSync(usersFilePath)) {
                const fileContent = fs.readFileSync(usersFilePath, 'utf8');
                if (fileContent.trim()) {
                    users = JSON.parse(fileContent);
                }
            }

            if (!users[username]) {
                users[username] = {};
            }
            
            users[username] = {
                ...users[username],
                profilePicture: `/profile_pictures/${username}/profile${fileExtension}?t=${Date.now()}`
            };

            fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));

        } catch (err) {
            console.error('Error saving profile:', err);
            return res.status(500).json({ error: 'Failed to save profile information: ' + err.message });
        }

        const publicPath = `/profile_pictures/${username}/profile${fileExtension}?t=${Date.now()}`;
        res.json({ 
            message: 'Profile picture uploaded successfully',
            path: publicPath
        });
    } catch (error) {
        if (req.file && fs.existsSync(req.file.path)) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (err) {
                console.error('Error cleaning up temp file:', err);
            }
        }
        console.error('Profile upload error:', error);
        res.status(500).json({ error: 'Failed to upload profile picture: ' + error.message });
    }
});

// Admin ZIP code - you should change this to your desired admin ZIP code
// Load admin ZIP codes from file
let adminZipCodes = [];
try {
    const adminData = JSON.parse(fs.readFileSync("admin.json", "utf8"));
    adminZipCodes = adminData.zipCodes || [];
} catch (error) {
    // Initialize with default admin.json if it doesn't exist
    adminZipCodes = ["1112"]; // Replace with your default admin ZIP code
    fs.writeFileSync("admin.json", JSON.stringify({ zipCodes: adminZipCodes }, null, 2));
}

app.get("/accounts", async (req, res) => {
    try {
        if (!fs.existsSync(LOGIN_USER_FILE)) {
            return res.json([]);
        }
        const users = JSON.parse(fs.readFileSync(LOGIN_USER_FILE, "utf8"));
        const accountList = Object.entries(users).map(([username, data]) => ({
            username,
            registrationDate: data.registrationDate || new Date().toISOString().split('T')[0]
        }));
        res.json(accountList);
    } catch (error) {
        console.error("Error loading accounts:", error);
        res.status(500).json({ error: "Failed to load accounts" });
    }
});

app.post("/verify-admin", function (req, res) {
    const { zipCode } = req.body;
    const userIp = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;

    try {
        const ipData = JSON.parse(fs.readFileSync(USER_IP_FILE, "utf8"));
        const userIpData = ipData.find(entry => entry.query === userIp);

        if (!userIpData || userIpData.zip !== zipCode) {
            return res.json({ error: "This zip code is not yours", success: false });
        }

        const isAdmin = adminZipCodes.includes(zipCode);
        res.json({ success: isAdmin });
    } catch (error) {
        res.status(500).json({ error: "Failed to verify admin" });
    }
});

app.post("/add-admin", (req, res) => {
    const { newZipCode } = req.body;
    if (!adminZipCodes.includes(newZipCode)) {
        adminZipCodes.push(newZipCode);
        fs.writeFileSync("admin.json", JSON.stringify({ zipCodes: adminZipCodes }, null, 2));
        res.json({ success: true });
    } else {
        res.status(400).json({ error: "Admin ZIP code already exists" });
    }
});

app.post("/delete-account", async (req, res) => {
    const { username } = req.body;
    try {
        const users = JSON.parse(fs.readFileSync(LOGIN_USER_FILE, "utf8"));
        if (users[username]) {
            delete users[username];
            fs.writeFileSync(LOGIN_USER_FILE, JSON.stringify(users, null, 2));

            // Also delete user's API keys file if it exists
            const keyFilePath = path.join(USERPANEL_DIR, `${username}.json`);
            if (fs.existsSync(keyFilePath)) {
                fs.unlinkSync(keyFilePath);
            }

            res.json({ success: true });
        } else {
            res.status(404).json({ error: "Account not found" });
        }
    } catch (error) {
        res.status(500).json({ error: "Failed to delete account" });
    }
});

app.get("/manage/account", (req, res) => {
    res.sendFile(path.join(__dirname, "accounts.html"));
});

app.post("/toggle-key-maintenance", authenticateToken, (req, res) => {
    try {
        const { apiKey, forceDisable } = req.body;
        if (!keysCache[apiKey]) {
            return res.status(404).json({ error: "API Key not found" });
        }

        if (!keysCache[apiKey].hasOwnProperty('maintenance')) {
            keysCache[apiKey].maintenance = false;
        }

        if (forceDisable) {
            keysCache[apiKey].maintenance = false;
        } else {
            keysCache[apiKey].maintenance = !keysCache[apiKey].maintenance;
        }

        saveKeys(req.user.username);

        return res.json({ 
            success: true, 
            maintenance: keysCache[apiKey].maintenance,
            message: keysCache[apiKey].maintenance ? "Maintenance mode enabled" : "Maintenance mode disabled"
        });
    } catch (error) {
        console.error("Error in toggle-key-maintenance:", error);
        return res.status(500).json({ 
            success: false, 
            error: "Failed to toggle maintenance mode"
        });
    }
});



// Initialize required directories
try {
    [USERPANEL_DIR, profilePicturesDir].forEach(dir => {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    });

    // Initialize config files if they don't exist
    if (!fs.existsSync(USER_IP_FILE)) {
        fs.writeFileSync(USER_IP_FILE, '[]', 'utf8');
    }
    if (!fs.existsSync(LOGIN_USER_FILE)) {
        fs.writeFileSync(LOGIN_USER_FILE, '{}', 'utf8');
    }
} catch (error) {
    console.error('Error initializing application:', error);
}

// Global error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(PORT, () => {
    console.log(`Your App is listening on PORT: @${PORT}`);
});