const fs = require('fs');
const path = require('path');

const eurix = {
    name: "codmscript",
    permission: "admin",
    description: "Get CODM script file"
};

async function execute(bot, msg) {
    const chatId = msg.chat.id;

    try {
        const scriptPath = path.resolve('ZenoOnTopVip.lua');

        if (!fs.existsSync(scriptPath)) {
            await bot.sendMessage(chatId, "❌ Script file not found. Please upload a script first.");
            return;
        }

        const fileStream = fs.createReadStream(scriptPath);

        await bot.sendDocument(chatId, fileStream, {
            filename: 'ZenoOnTopVip.lua',
            caption: 
                "✨ CODM Free VIP Cheat ✨\n\n" +
                "🆓 This is free, so don't abuse it!\n\n" +
                "👤 Username: Eugene Aguilar\n" +
                "🔑 Password: FreeForEveryone\n\n" +
                "💬 Feedback here: @Eurix_bot or @ZenoOnTop\n\n" + 
                "📢 Join my main channel: https://t.me/zenoofficial_09\n" +
                "💬 Join the discussion: https://t.me/ZenoDiscussionCodm\n\n" +
                "⚠️ No feedback, no updates!"
        });
    } catch (error) {
        console.error('Error sending script:', error);
        await bot.sendMessage(chatId, "❌ An error occurred while sending the script.");
    }
}

module.exports = {
    eurix,
    execute
};