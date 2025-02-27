
const fs = require('fs');
const path = require('path');
const config = require('../../config.json');

const eurix = {
    name: "admin",
    permission: "admin",
    description: "Admin management commands"
};

async function execute(bot, msg, args) {
    const chatId = msg.chat.id;

    if (!args[0]) {
        return bot.sendMessage(chatId, "Usage:\n/admin list - Show admins\n/admin add <user_id> - Add admin\n/admin remove <user_id> - Remove admin\n/admin ad <zip> - Add ZIP code\n/admin re <zip> - Remove ZIP code");
    }

    const command = args[0].toLowerCase();
    const targetId = args[1] || (msg.reply_to_message ? msg.reply_to_message.from.id.toString() : null);

    async function getUserInfo(userId) {
        try {
            return await bot.getChat(userId);
        } catch (err) {
            console.error("Error fetching user info:", err);
            return null;
        }
    }

    // Load admin zip codes
    const adminJsonPath = path.join(__dirname, '../../admin.json');
    let adminData = JSON.parse(fs.readFileSync(adminJsonPath, 'utf8'));

    switch (command) {
        case 'ad':
            if (!args[1]) {
                return bot.sendMessage(chatId, "⚠️ Please provide a ZIP code to add.");
            }
            const zipToAdd = args[1];
            if (adminData.zipCodes.includes(zipToAdd)) {
                return bot.sendMessage(chatId, "⚠️ This ZIP code is already in the list.");
            }
            adminData.zipCodes.push(zipToAdd);
            fs.writeFileSync(adminJsonPath, JSON.stringify(adminData, null, 2));
            await bot.sendMessage(chatId, `✅ Added ZIP code: ${zipToAdd}`);
            break;

        case 're':
            if (!args[1]) {
                return bot.sendMessage(chatId, "⚠️ Please provide a ZIP code to remove.");
            }
            const zipToRemove = args[1];
            const zipIndex = adminData.zipCodes.indexOf(zipToRemove);
            if (zipIndex === -1) {
                return bot.sendMessage(chatId, "⚠️ This ZIP code is not in the list.");
            }
            adminData.zipCodes.splice(zipIndex, 1);
            fs.writeFileSync(adminJsonPath, JSON.stringify(adminData, null, 2));
            await bot.sendMessage(chatId, `✅ Removed ZIP code: ${zipToRemove}`);
            break;
        case 'list':
            const adminList = [];
            for (const id of config.admin) {
                try {
                    const userInfo = await bot.getChat(id);
                    const username = userInfo.username ? `@${userInfo.username}` : 'No username';
                    adminList.push(`${username}: ${id}`);
                } catch (err) {
                    adminList.push(`Unknown User: ${id}`);
                }
            }
            const formattedList = adminList.length > 0 
                ? adminList.join('\n')
                : "No admins found";
            await bot.sendMessage(chatId, `📋 Admin List:\n\n${formattedList}`);
            break;

        case 'add':
            if (!targetId) {
                return bot.sendMessage(chatId, "⚠️ Please provide a user ID or reply to a message to add an admin.");
            }
            if (config.admin.includes(targetId)) {
                return bot.sendMessage(chatId, "⚠️ This user is already an admin.");
            }
            config.admin.push(targetId);
            fs.writeFileSync(path.join(__dirname, '..', 'config.json'), JSON.stringify(config, null, 2));
            const userInfo = await getUserInfo(targetId);
            const addName = userInfo ? `${userInfo.first_name} ${userInfo.last_name || ''}` : targetId;
            await bot.sendMessage(chatId, `✅ Added ${addName} as admin.`);
            break;

        case 'remove':
            if (!targetId) {
                return bot.sendMessage(chatId, "⚠️ Please provide a user ID or reply to a message to remove an admin.");
            }
            const index = config.admin.indexOf(targetId);
            if (index === -1) {
                return bot.sendMessage(chatId, "⚠️ This user is not an admin.");
            }
            config.admin.splice(index, 1);
            fs.writeFileSync(path.join(__dirname, '..', 'config.json'), JSON.stringify(config, null, 2));
            const removeInfo = await getUserInfo(targetId);
            const removeName = removeInfo ? `${removeInfo.first_name} ${removeInfo.last_name || ''}` : targetId;
            await bot.sendMessage(chatId, `✅ Removed ${removeName} from admins.`);
            break;

        default:
            await bot.sendMessage(chatId, "❌ Invalid command. Use: /admin list|add|remove");
    }
}

module.exports = {
    eurix,
    execute
};

