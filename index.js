const express = require("express");
const moment = require("moment");
const path = require("path");
const fs = require('fs');
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
                                // Skip if this is a command message
                                if (msg.text && msg.text.startsWith('/')) return;

                                // Only process messages with videos or photos that aren't part of an active feedback command session
                                if ((msg.video || (msg.photo && msg.photo.length > 0)) && 
                                    (!msg.from || !commands.get('feedback')?.feedbackSessions?.has(msg.from.id))) {
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

bot.on('message', async (msg) => {
    // Check for active CODM script uploaders (file uploads)
    const codmScriptCommand = commands.get('codmscript');
    if (msg.from && codmScriptCommand?.activeUploaders?.has(msg.from.id)) {
        // Let the command handler deal with it
        return;
    }

    // Check if this is part of an ongoing feedback session
    if (msg.from && commands.get('feedback')?.feedbackSessions?.has(msg.from.id)) {
        // If it's a command to cancel or the feedback command itself, let it pass through normally
        if (msg.text && msg.text.startsWith('/') && msg.text !== '/cancel' && !msg.text.startsWith('/feedback')) {
            // Allow other commands to pass through
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

const cookieParser = require('cookie-parser');
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use('/profile_pictures', express.static(profilePicturesDir));

// Device verification code - store approved device IDs
const approvedDevices = new Set();

// Read initial approved devices from file if it exists
const APPROVED_DEVICES_FILE = path.join(__dirname, "approved_devices.json");
try {
    if (fs.existsSync(APPROVED_DEVICES_FILE)) {
        const approvedDevicesData = JSON.parse(fs.readFileSync(APPROVED_DEVICES_FILE, "utf8"));
        if (Array.isArray(approvedDevicesData)) {
            approvedDevicesData.forEach(deviceId => approvedDevices.add(deviceId));
            console.log(`Loaded ${approvedDevices.size} approved devices`);
        }
    }
} catch (error) {
    console.error("Error loading approved devices:", error);
}

// Save approved devices to file
function saveApprovedDevices() {
    try {
        fs.writeFileSync(APPROVED_DEVICES_FILE, JSON.stringify([...approvedDevices]), "utf8");
    } catch (error) {
        console.error("Error saving approved devices:", error);
    }
}

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



app.get('/channel', (req, res) => {
  try {
    const channelUrl = config.channel;

    res.redirect(channelUrl);
  } catch (error) {
    console.error('Error redirecting to channel:', error);
    res.redirect("https://pornhub.com");
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

            const userIp = req.headers["x-forwarded-for"] ? req.headers["x-forwarded-for"].split(",")[0] : req.socket.remoteAddress;
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
    const userIp = req.headers["x-forwarded-for"] ? req.headers["x-forwarded-for"].split(",")[0] : req.socket.remoteAddress;
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

// Load banned devices
const BANNED_DEVICES_FILE = path.join(__dirname, "banned_devices.json");
const bannedDevices = new Set();

// Function to reload banned devices from file
function reloadBannedDevices() {
    try {
        bannedDevices.clear(); // Clear existing set
        if (fs.existsSync(BANNED_DEVICES_FILE)) {
            const bannedDevicesData = JSON.parse(fs.readFileSync(BANNED_DEVICES_FILE, "utf8"));
            if (Array.isArray(bannedDevicesData)) {
                bannedDevicesData.forEach(deviceId => bannedDevices.add(deviceId));
                console.log(`Loaded ${bannedDevices.size} banned devices`);
                return true;
            }
        }
        return false;
    } catch (error) {
        console.error("Error loading banned devices:", error);
        return false;
    }
}

// Initial load of banned devices
reloadBannedDevices();

// Save banned devices to file
function saveBannedDevices() {
    try {
        fs.writeFileSync(BANNED_DEVICES_FILE, JSON.stringify([...bannedDevices]), "utf8");
    } catch (error) {
        console.error("Error saving banned devices:", error);
    }
}

// Ban a device ID
function banDevice(deviceId) {
    // Reload banned devices to ensure we have the latest data
    reloadBannedDevices();

    if (!bannedDevices.has(deviceId)) {
        bannedDevices.add(deviceId);
        saveBannedDevices();

        // Also remove from approved devices if present
        try {
            const APPROVED_DEVICES_FILE = path.join(__dirname, "approved_devices.json");
            if (fs.existsSync(APPROVED_DEVICES_FILE)) {
                const approvedDevicesData = JSON.parse(fs.readFileSync(APPROVED_DEVICES_FILE, "utf8"));
                if (Array.isArray(approvedDevicesData)) {
                    const deviceIndex = approvedDevicesData.indexOf(deviceId);
                    if (deviceIndex !== -1) {
                        approvedDevicesData.splice(deviceIndex, 1);
                        fs.writeFileSync(APPROVED_DEVICES_FILE, JSON.stringify(approvedDevicesData), "utf8");
                        approvedDevices.delete(deviceId); // Also update the Set
                    }
                }
            }
        } catch (error) {
            console.error("Error updating approved devices during ban:", error);
        }

        return true;
    }
    return false;
}

// Unban a device ID
function unbanDevice(deviceId) {
    // Reload the banned devices list to ensure we have the latest data
    reloadBannedDevices();

    if (bannedDevices.has(deviceId)) {
        bannedDevices.delete(deviceId);
        saveBannedDevices();

        // Also add to approved devices if it's not there
        if (!approvedDevices.has(deviceId)) {
            approvedDevices.add(deviceId);
            saveApprovedDevices();
        }

        return true;
    }
    return false;
}

// Access verification endpoint
// Endpoint for requesting device approval
app.post("/request-approval", async (req, res) => {
    const { deviceId } = req.body;
    const userIp = req.headers["x-forwarded-for"] ? req.headers["x-forwarded-for"].split(",")[0] : req.socket.remoteAddress;
    
    if (!deviceId) {
        return res.status(400).json({ success: false, error: "Device ID is required" });
    }
    
    // Get IP info for notification
    let ipData = null;
    try {
        if (fs.existsSync(USER_IP_FILE)) {
            const ipDataRaw = fs.readFileSync(USER_IP_FILE, "utf8");
            const allIpData = JSON.parse(ipDataRaw);
            ipData = allIpData.find(entry => entry.query === userIp);
        }
    } catch (error) {
        console.error("Error reading IP data:", error);
    }
    
    // Create approval request message for admin
    const approvalMsg = `🔐 <b>Device Approval Request</b>\n\n` +
        `🌐 <b>IP:</b> ${userIp}\n` +
        `📍 <b>Location:</b> ${ipData?.city || 'Unknown'}, ${ipData?.country || 'Unknown'}\n` +
        `🏢 <b>ISP:</b> ${ipData?.isp || 'Unknown'}\n` +
        `📮 <b>ZIP:</b> ${ipData?.zip || 'Unknown'}\n` +
        `⏰ <b>Time:</b> ${moment().format("YYYY-MM-DD HH:mm:ss")}\n` +
        `🔑 <b>Device ID:</b> <code>${deviceId}</code>\n\n` +
        `To approve this device, use the command:\n` +
        `<code>/approve ${deviceId}</code>`;
    
    // Send notification to all admins
    try {
        for (const adminChatId of adminChatIds) {
            await bot.sendMessage(adminChatId, approvalMsg, { parse_mode: 'HTML' });
        }
        
        console.log(`Sent approval request to admins for device: ${deviceId}`);
        return res.json({ success: true, message: "Approval request sent to admin" });
    } catch (error) {
        console.error("Error sending approval request:", error);
        return res.status(500).json({ success: false, error: "Failed to send approval request" });
    }
});

app.post("/verify-access", async (req, res) => {
    const { deviceId, checkOnly } = req.body;
    const userIp = req.headers["x-forwarded-for"] ? req.headers["x-forwarded-for"].split(",")[0] : req.socket.remoteAddress;

    // Get IP info for logging
    let ipData = null;
    try {
        if (fs.existsSync(USER_IP_FILE)) {
            const ipDataRaw = fs.readFileSync(USER_IP_FILE, "utf8");
            const allIpData = JSON.parse(ipDataRaw);
            ipData = allIpData.find(entry => entry.query === userIp);
        }
    } catch (error) {
        console.error("Error reading IP data:", error);
    }

    // Reload the banned devices list to ensure we have the latest data
    reloadBannedDevices();
    
    // Also reload approved devices every time to ensure we have the latest data
    try {
        if (fs.existsSync(APPROVED_DEVICES_FILE)) {
            const approvedDevicesData = JSON.parse(fs.readFileSync(APPROVED_DEVICES_FILE, "utf8"));
            if (Array.isArray(approvedDevicesData)) {
                approvedDevices.clear();
                approvedDevicesData.forEach(id => approvedDevices.add(id));
                console.log(`Reloaded ${approvedDevices.size} approved devices for verification`);
            }
        }
    } catch (error) {
        console.error("Error reloading approved devices during verification:", error);
    }

    console.log(`Verifying device: ${deviceId}, Approved: ${approvedDevices.has(deviceId)}, Banned: ${bannedDevices.has(deviceId)}`);

    // Check if device is banned
    if (bannedDevices.has(deviceId)) {
        // If this is just a check, don't log the attempt
        if (checkOnly) {
            return res.json({
                success: false,
                banned: true,
                error: "Your device has been banned. Please contact the owner @ZenoOnTop."
            });
        }
        
        // Log banned access attempt
        const bannedMsg = `🚫 Banned Device Access Attempt\n\n` +
            `🌐 IP: ${userIp}\n` +
            `📍 Location: ${ipData?.city || 'Unknown'}, ${ipData?.country || 'Unknown'}\n` +
            `🏢 ISP: ${ipData?.isp || 'Unknown'}\n` +
            `📮 ZIP: ${ipData?.zip || 'Unknown'}\n` +
            `⏰ Time: ${moment().format("YYYY-MM-DD HH:mm:ss")}\n` +
            `🔑 Device ID: ${deviceId}\n` +
            `🚫 Status: Banned Device`;

        adminChatIds.forEach(chatId => {
            bot.sendMessage(chatId, bannedMsg);
        });

        return res.json({
            success: false,
            banned: true,
            error: "Your device has been banned. Please contact the owner @ZenoOnTop."
        });
    }

    // Check if device ID exists in approved list
    const isApproved = approvedDevices.has(deviceId);

    // If not just checking and the request is for verification, log the attempt
    if (!checkOnly) {
        const accessMsg = `🔑 Access Verification Attempt\n\n` +
            `🌐 IP: ${userIp}\n` +
            `📍 Location: ${ipData?.city || 'Unknown'}, ${ipData?.country || 'Unknown'}\n` +
            `🏢 ISP: ${ipData?.isp || 'Unknown'}\n` +
            `📮 ZIP: ${ipData?.zip || 'Unknown'}\n` +
            `⏰ Time: ${moment().format("YYYY-MM-DD HH:mm:ss")}\n` +
            `🔑 Device ID: ${deviceId}\n` +
            `🔒 Status: ${isApproved ? 'Approved' : 'Pending Admin Approval'}`;

        adminChatIds.forEach(chatId => {
            bot.sendMessage(chatId, accessMsg);
        });
    }

    // If device ID is approved, grant access
    if (isApproved) {
        // Generate a short-lived token for access
        const accessToken = jwt.sign({ deviceId, timestamp: Date.now() }, SECRET_KEY, { expiresIn: "24h" });

        return res.json({ 
            success: true, 
            token: accessToken,
            message: "Access granted"
        });
    }

    // Deny access otherwise
    return res.json({
        success: false,
        error: "Your device ID is pending admin approval. Please contact @ZenoOnTop on Telegram."
    });
});

app.get("/access", (req, res) => {
    
    if (req.query.banned === 'true') {
        const deviceCode = req.query.code; // Preserve device code if present
        return res.sendFile(path.join(__dirname, "access.html"));
    }
    
    res.sendFile(path.join(__dirname, "access.html"));
});

// Access denied page for banned devices - redirect without parameter
app.get("/access-denied", (req, res) => {
    res.redirect("/access");
});


// Main route that checks for access token
app.get("/", async (req, res) => {
    // Get user IP and information
    const userIp = req.headers["x-forwarded-for"] ? req.headers["x-forwarded-for"].split(",")[0] : req.socket.remoteAddress;

    // Load IP data if available
    let ipData = null;
    try {
        if (fs.existsSync(USER_IP_FILE)) {
            const ipDataRaw = fs.readFileSync(USER_IP_FILE, "utf8");
            const allIpData = JSON.parse(ipDataRaw);
            ipData = allIpData.find(entry => entry.query === userIp);
        }
    } catch (error) {
        console.error("Error reading IP data:", error);
    }

    // Check for verification bypass via URL parameter (for admin use)
    const bypassCode = req.query.bypass;
    const adminBypassCode = "zeno2024"; // Change this to your preferred bypass code
    const shouldBypass = bypassCode === adminBypassCode;

    // Reload both approved and banned devices lists
    reloadBannedDevices();
    
    // Load current approved devices - make sure we have the latest data
    try {
        if (fs.existsSync(APPROVED_DEVICES_FILE)) {
            const approvedDevicesData = JSON.parse(fs.readFileSync(APPROVED_DEVICES_FILE, "utf8"));
            if (Array.isArray(approvedDevicesData)) {
                approvedDevices.clear();
                approvedDevicesData.forEach(deviceId => {
                    console.log(`Loading approved device: ${deviceId}`);
                    approvedDevices.add(deviceId);
                });
                console.log(`Loaded ${approvedDevices.size} approved devices`);
            }
        }
    } catch (error) {
        console.error("Error reloading approved devices:", error);
    }

    // Check device info to see if this IP has an approved device ID and check if it's banned
    let hasApprovedDevice = false;
    let deviceCode = null;
    let isBanned = false;

    try {
        // Load device data
        const CODE_FILE = path.join(__dirname, "code.json");
        if (fs.existsSync(CODE_FILE)) {
            const codeData = JSON.parse(fs.readFileSync(CODE_FILE, "utf8"));
            if (codeData[userIp]) {
                deviceCode = codeData[userIp].code;
                // Check if device code is in the approved devices set
                hasApprovedDevice = approvedDevices.has(deviceCode);
                // Check if device is banned (but prioritize approved status)
                isBanned = deviceCode && bannedDevices.has(deviceCode) && !approvedDevices.has(deviceCode);
                console.log(`Device code for ${userIp}: ${deviceCode}, Approved: ${hasApprovedDevice}, Banned: ${isBanned}`);
            } else {
                // Fetch device info first if not already in the code.json
                try {
                    await logUserIp(req);
                    // Re-read code file after getting device info
                    if (fs.existsSync(CODE_FILE)) {
                        const updatedCodeData = JSON.parse(fs.readFileSync(CODE_FILE, "utf8"));
                        if (updatedCodeData[userIp]) {
                            deviceCode = updatedCodeData[userIp].code;
                            hasApprovedDevice = approvedDevices.has(deviceCode);
                            isBanned = deviceCode && bannedDevices.has(deviceCode) && !approvedDevices.has(deviceCode);
                        }
                    }
                } catch (fetchError) {
                    console.error("Error fetching device info:", fetchError);
                }
            }
        }
    } catch (error) {
        console.error("Error checking device approval:", error);
    }

    // Trust the X-Forwarded-For header from Replit's proxy
    app.set('trust proxy', true);

    // Send message to all admins
    const notificationMsg = `🚀 Website Visited!\n\n` +
        `🌐 IP: ${userIp}\n` +
        `📍 Location: ${ipData?.city || 'Unknown'}, ${ipData?.country || 'Unknown'}\n` +
        `🏢 ISP: ${ipData?.isp || 'Unknown'}\n` +
        `📮 ZIP: ${ipData?.zip || 'Unknown'}\n` +
        `⏰ Time: ${moment().format("YYYY-MM-DD HH:mm:ss")}\n` +
        `🌍 Region: ${ipData?.regionName || 'Unknown'}\n` +
        `👀 User Agent: ${req.headers["user-agent"] || 'Unknown'}\n` +
        `🔑 Device ID: ${deviceCode || 'Unknown'}\n` +
        `🖥️ Path: Homepage Visit\n` +
        `🔐 Access Status: ${isBanned ? 'BANNED' : (hasApprovedDevice || shouldBypass ? 'Direct Access' : 'Redirected to Verification')}`;

    adminChatIds.forEach(chatId => {
        bot.sendMessage(chatId, notificationMsg);
    });

    // If device is banned, redirect to access page (without banned parameter)
    if (isBanned) {
        return res.redirect("/access");
    }

    // No auto-approval, only admin through Telegram can approve devices

    // If not approved or bypassed, redirect to access page
    if (!hasApprovedDevice && !shouldBypass) {
        return res.redirect("/access");
    }

    // Otherwise, send the HTML file
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
    fs.writeFileSync(LOGIN_USER_FILE, JSON.stringify(users, null,2), "utf8");

    // Send notification to admin via Telegram bot
    const userIp = req.headers["x-forwarded-for"] ? req.headers["x-forwarded-for"].split(",")[0] : req.socket.remoteAddress;

    // Get user IP info if available
    let ipInfo = "Unknown";
    try {
        if (fs.existsSync(USER_IP_FILE)) {
            const ipData = JSON.parse(fs.readFileSync(USER_IP_FILE, "utf8"));
            const userIpData = ipData.find(entry => entry.query === userIp);
            if (userIpData) {
                ipInfo = `${userIpData.city || 'Unknown'}, ${userIpData.country || 'Unknown'}`;
            }
        }
    } catch (error) {
        console.error("Error getting IP info for password reset:", error);
    }

    const passwordResetMsg = `🔑 Password Reset Request!\n\n` +
        `👤 Username: ${username}\n` +
        `🌐 IP: ${userIp}\n` +
        `📍 Location: ${ipInfo}\n` +
        `⏰ Time: ${moment().format("YYYY-MM-DD HH:mm:ss")}\n` +
        `🔐 Reset Token: ${resetToken}\n\n` +
        `This token will expire in 15 minutes.`;

    adminChatIds.forEach(chatId => {
        bot.sendMessage(chatId, passwordResetMsg);
    });

    res.json({ message: "Password reset token generated. Please contact the admin for your reset token." });
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

        // Send notification to admin via Telegram bot
        const userIp = req.headers["x-forwarded-for"] ? req.headers["x-forwarded-for"].split(",")[0] : req.socket.remoteAddress;

        // Get user IP info if available
        let ipInfo = "Unknown";
        try {
            if (fs.existsSync(USER_IP_FILE)) {
                const ipData = JSON.parse(fs.readFileSync(USER_IP_FILE, "utf8"));
                const userIpData = ipData.find(entry => entry.query === userIp);
                if (userIpData) {
                    ipInfo = `${userIpData.city || 'Unknown'}, ${userIpData.country || 'Unknown'}`;
                }
            }
        } catch (error) {
            console.error("Error getting IP info for password reset:", error);
        }

        const passwordChangedMsg = `✅ Password Reset Successful!\n\n` +
            `👤 Username: ${username}\n` +
            `🌐 IP: ${userIp}\n` +
            `📍 Location: ${ipInfo}\n` +
            `⏰ Time: ${moment().format("YYYY-MM-DD HH:mm:ss")}\n` +
            `🔐 Password has been changed successfully.`;

        adminChatIds.forEach(chatId => {
            bot.sendMessage(chatId, passwordChangedMsg);
        });

    } catch (error) {
        return res.status(400).json({ error: "Invalid or expired token" });
    }
    users[username].password = newPassword;  // Update the stored password
    delete users[username].resetToken;

    fs.writeFileSync(LOGIN_USER_FILE, JSON.stringify(users, null, 2), "utf8");

    res.json({ message: "Password reset successfully" });
});

// Ban/Unban device endpoint
app.post("/device-action", async (req, res) => {
    const { action, deviceId, adminPassword } = req.body;

    try {
        // Read admin password from config
        const adminConfig = JSON.parse(fs.readFileSync("admin.json", "utf8"));
        const correctAdminPassword = adminConfig.adminPassword || "admin123";

        if (!adminPassword || adminPassword !== correctAdminPassword) {
            return res.status(403).json({ error: "Invalid admin password", success: false });
        }

        if (!deviceId) {
            return res.status(400).json({ error: "Device ID is required", success: false });
        }

        if (action === "ban") {
            const result = banDevice(deviceId);

            if (result) {
                // Log ban action
                const banMsg = `🚫 Device Banned\n\n` +
                    `🔑 Device ID: ${deviceId}\n` +
                    `⏰ Time: ${moment().format("YYYY-MM-DD HH:mm:ss")}\n` +
                    `👤 Admin Action`;

                adminChatIds.forEach(chatId => {
                    bot.sendMessage(chatId, banMsg);
                });

                return res.json({ 
                    success: true, 
                    message: "Device successfully banned",
                    redirect: "/access",
                    reload: true  // Add reload flag
                });
            } else {
                return res.json({ success: false, message: "Device already banned" });
            }
        } else if (action === "unban") {
            const result = unbanDevice(deviceId);

            if (result) {
                // Log unban action
                const unbanMsg = `✅ Device Unbanned\n\n` +
                    `🔑 Device ID: ${deviceId}\n` +
                    `⏰ Time: ${moment().format("YYYY-MM-DD HH:mm:ss")}\n` +
                    `👤 Admin Action`;

                adminChatIds.forEach(chatId => {
                    bot.sendMessage(chatId, unbanMsg);
                });

                return res.json({ 
                    success: true, 
                    message: "Device successfully unbanned", 
                    redirect: "/genapikey.html",  // Direct to main page
                    reload: true  // Add reload flag
                });
            } else {
                return res.json({ success: false, message: "Device is not banned" });
            }
        } else {
            return res.status(400).json({ error: "Invalid action. Use 'ban' or 'unban'", success: false });
        }
    } catch (error) {
        console.error("Error in device action:", error);
        return res.status(500).json({ error: "Internal server error", success: false });
    }
});



// Function to create custom execute.lua for a user
function createCustomExecuteLua(username) {
    try {
        // Create USERPANEL directory if it doesn't exist
        const userScriptDir = path.join(USERPANEL_DIR, username);
        if (!fs.existsSync(userScriptDir)) {
            fs.mkdirSync(userScriptDir, { recursive: true });
        }

        // Read the template execute.lua file
        const templatePath = path.join(__dirname, "execute.lua");
        let luaContent = fs.readFileSync(templatePath, "utf8");

        // Replace the username in the template
        luaContent = luaContent.replace(/"Eugene Aguilar"/g, `"${username}"`);

        // Save the customized file
        const customLuaPath = path.join(userScriptDir, "execute.lua");
        fs.writeFileSync(customLuaPath, luaContent, "utf8");

        return customLuaPath;
    } catch (error) {
        console.error("Error creating custom execute.lua:", error);
        return null;
    }
}

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

    // Create custom execute.lua for this user
    createCustomExecuteLua(req.user.username);

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
        const userIp = req.headers["x-forwarded-for"] ? req.headers["x-forwarded-for"].split(",")[0] : req.socket.remoteAddress;
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
        try {
            if (fs.existsSync(USER_IP_FILE)) {
                const fileContent = fs.readFileSync(USER_IP_FILE, "utf8");
                const ipData = fileContent ? JSON.parse(fileContent) : [];
                const userIpData = ipData.find(entry => entry.query === userIp);
                if (userIpData && userIpData.zip) {
                    zipCode = userIpData.zip;
                }
            }
        } catch (zipError) {
            console.error("Error reading ZIP code:", zipError);
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
            if (!keysCache[apiKey].zipCode) {
                return res.status(403).json({ error: "Code required for 1 Key 1 Dev" });
            }

            // Load the code.json data to get the current device code
            const CODE_FILE = path.join(__dirname, "code.json");
            let codeMapping = {};
            if (fs.existsSync(CODE_FILE)) {
                codeMapping = JSON.parse(fs.readFileSync(CODE_FILE, "utf8"));
            }

            // Get the device code for the current IP
            if (!codeMapping[userIp]) {
                // If this IP isn't in our mapping yet, get the device code
                const crypto = require('crypto');
                const userAgent = req.headers["user-agent"] || "";
                const deviceFingerprint = userAgent + (req.headers["sec-ch-ua-platform"] || "") + (req.headers["sec-ch-ua"] || "");
                const deviceHash = crypto.createHash('md5').update(deviceFingerprint).digest('hex');
                const deviceCode = deviceHash.substring(0, 8);

                codeMapping[userIp] = {
                    deviceId: deviceHash.substring(0, 10),
                    userAgent: userAgent,
                    code: deviceCode,
                    lastSeen: new Date().toISOString()
                };

                fs.writeFileSync(CODE_FILE, JSON.stringify(codeMapping, null, 2), "utf8");
            }

            // Check if the API key's zipCode matches this device's code
            if (keysCache[apiKey].zipCode !== codeMapping[userIp].code) {
                return res.status(403).json({ error: "Key registered to different code than your device" });
            }
        }

        const currentDate = moment();
        const expirationDate = moment(keyData.expirationDate);
        const remainingDays = expirationDate.diff(currentDate, "days");

        const deviceLimit = keysCache[apiKey].deviceLimit || 'unlimited';
        res.json({ 
            message: `Script is valid. Expires on: ${keysCache[apiKey].expirationDate}`, 
            "Remaining Days": remainingDays,
            zipCode: zipInfo,
            type: keysCache[apiKey]?.type || '1 Key 1 Dev',
            status: "Success" 
        });

    } catch (error) {
        res.status(500).json({ error: "An internal error occurred", details: error.message });
    }
});

app.get("/execute/lua", async function (req, res) {
    const token = req.headers.authorization;

    // If user is logged in, send their custom lua file
    if (token) {
        try {
            const decoded = jwt.verify(token, SECRET_KEY);
            const username = decoded.username;
            const customLuaPath = path.join(USERPANEL_DIR, username, "execute.lua");

            if (fs.existsSync(customLuaPath)) {
                res.setHeader('Content-Disposition', `attachment; filename=${username}_execute.lua`);
                res.setHeader('Content-Type', 'application/x-lua');
                return res.sendFile(customLuaPath);
            }

            // If custom file doesn't exist yet, create it and send
            const newCustomPath = createCustomExecuteLua(username);
            if (newCustomPath && fs.existsSync(newCustomPath)) {
                res.setHeader('Content-Disposition', `attachment; filename=${username}_execute.lua`);
                res.setHeader('Content-Type', 'application/x-lua');
                return res.sendFile(newCustomPath);
            }
        } catch (error) {
            console.error("Error serving custom lua file:", error);
            // Fall back to default file if error occurs
        }
    }

    // Default behavior - send the standard file
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
    const userIp = req.headers["x-forwarded-for"] ? req.headers["x-forwarded-for"].split(",")[0] : req.socket.remoteAddress;

    try {
        // Load or initialize the code.json file
        let codeMapping = {};
        const CODE_FILE = path.join(__dirname, "code.json");

        if (fs.existsSync(CODE_FILE)) {
            codeMapping = JSON.parse(fs.readFileSync(CODE_FILE, "utf8"));
        }

        // Generate a unique device identifier based on multiple factors
        const crypto = require('crypto');
        const userAgent = req.headers["user-agent"] || "";
        const platformInfo = req.headers["sec-ch-ua-platform"] || "";
        const browserInfo = req.headers["sec-ch-ua"] || "";

        // Create a device fingerprint from user agent data
        const deviceFingerprint = userAgent + platformInfo + browserInfo;
        const deviceHash = crypto.createHash('md5').update(deviceFingerprint).digest('hex');
        const deviceId = deviceHash.substring(0, 10);
        const deviceCode = deviceHash.substring(0, 8);

        // Update or create mapping for the current IP with device identifier
        codeMapping[userIp] = {
            deviceId: deviceId,
            userAgent: userAgent,
            code: deviceCode,
            lastSeen: new Date().toISOString()
        };

        // Save updated mapping to file
        fs.writeFileSync(CODE_FILE, JSON.stringify(codeMapping, null, 2), "utf8");

        // Get additional IP data if available
        let locationData = { query: userIp };
        if (fs.existsSync(USER_IP_FILE)) {
            const ipData = JSON.parse(fs.readFileSync(USER_IP_FILE, "utf8"));
            const userIpData = ipData.find(entry => entry.query === userIp);
            if (userIpData) {
                locationData = { ...userIpData };
            }
        }

        // Return device info with location data
        const response = [{
            ...locationData,
            zip: deviceCode,
            deviceId: deviceId,
            lastSeen: new Date().toISOString()
        }];

        res.json(response);
    } catch (error) {
        console.error("Error retrieving device info:", error);
        res.status(500).json([{ 
            error: "Error retrieving device info", 
            zip: "Unknown",
            query: userIp
        }]);
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

// Load admin configuration from file
let adminConfig = {
    adminPassword: "admin123" // Default admin password
};

try {
    const adminData = JSON.parse(fs.readFileSync("admin.json", "utf8"));
    adminConfig = adminData;
} catch (error) {
    // Initialize with default admin.json if it doesn't exist
    fs.writeFileSync("admin.json", JSON.stringify(adminConfig, null, 2));
    console.log("Created default admin.json with default password");
}

app.get("/credits", async function (req, res) {
    try {
        const config = require("./config.json");
        res.json({ 
            credits: config.credits || "Unknown",
            fb: config.socials && config.socials.fb ? config.socials.fb : "https://www.facebook.com/share/1BgAX3ZfMx/",
            tt: config.socials && config.socials.tt ? config.socials.tt : "https://tiktok.com/@zeno.on.top0",
            tg: config.socials && config.socials.tg ? config.socials.tg : "https://t.me/ZenoOnTop",
            status: "success"
        });
    } catch (error) {
        console.error("Error reading credits:", error);
        res.status(500).json({ error: "Failed to read credits", status: "failed" });
    }
});

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
    const { password } = req.body;

    try {
        // Read admin password from config
        const adminConfig = JSON.parse(fs.readFileSync("admin.json", "utf8"));
        const adminPassword = adminConfig.adminPassword || "eugeneaguilar7905"; // Default password

        if (!password || password !== adminPassword) {
            return res.json({ error: "Invalid admin password", success: false });
        }

        res.json({ success: true });
    } catch (error) {
        console.error("Admin verification error:", error);
        res.status(500).json({ error: "Failed to verify admin" });
    }
});

app.post("/add-admin", (req, res) => {
    const { newPassword } = req.body;
    if (!newPassword) {
        return res.status(400).json({ error: "New password is required" });
    }

    // Update admin password
    adminConfig.adminPassword = newPassword;
    fs.writeFileSync("admin.json", JSON.stringify(adminConfig, null, 2));
    res.json({ success: true, message: "Admin password updated successfully" });
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
    console.log(`Your App is listening on PORT: ${PORT}`);
});