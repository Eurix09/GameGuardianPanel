
const fs = require('fs');
const path = require('path');

const eurix = {
    name: "iplist",
    description: "Show list of IP addresses",
    permission: "admin"
};

async function execute(bot, msg) {
    const chatId = msg.chat.id;
    const config = require('../../config.json');
    
    if (!config.admin.includes(msg.from.id.toString())) {
        return bot.sendMessage(chatId, "❌ You are not authorized to use this command.");
    }

    try {
        const ipFile = path.join(process.cwd(), 'UserIp.json');
        await bot.sendDocument(chatId, ipFile, {
            caption: "Here's the list of User IPs",
            parse_mode: 'Markdown'
        });
    } catch (error) {
        console.error('Error in iplist command:', error);
        await bot.sendMessage(chatId, "❌ Error occurred while fetching IP information.");
    }
}

module.exports = {
    eurix,
    execute
};
