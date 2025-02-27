
const fs = require('fs');
const path = require('path');

const eurix = {
    name: "account",
    permission: "admin",
    description: "Show account and key list"
};

async function execute(bot, msg) {
    const chatId = msg.chat.id;

    try {
        // Read login users file
        const loginUserFile = path.join(__dirname, '..', 'LoginUser.json');
        const users = fs.existsSync(loginUserFile) ? JSON.parse(fs.readFileSync(loginUserFile, 'utf8')) : {};
        
        // Create account list message
        let accountMsg = "📋 *Account List:*\n\n";
        Object.keys(users).forEach(username => {
            accountMsg += `👤 Username: ${username}\n🔑 Password: ${users[username].password}\n\n`;
        });

        // Send account list
        await bot.sendMessage(chatId, accountMsg, { parse_mode: 'Markdown' });

        // Send each user's key file
        const userPanelDir = path.join(__dirname, '..', 'USERPANEL');
        for (const username of Object.keys(users)) {
            const keyFile = path.join(userPanelDir, `${username}.json`);
            if (fs.existsSync(keyFile)) {
                await bot.sendDocument(chatId, keyFile, {
                    caption: `🔑 Keys for user: ${username}`
                });
            }
        }
    } catch (error) {
        console.error('Error in account command:', error);
        await bot.sendMessage(chatId, "❌ Error occurred while fetching account information.");
    }
}

module.exports = {
    eurix,
    execute
};
