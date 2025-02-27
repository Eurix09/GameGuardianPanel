
const axios = require('axios');

const eurix = {
    name: "shoti",
    description: "Get random Shoti video"
};

async function execute(bot, msg) {
    const chatId = msg.chat.id;
    
    try {
        await bot.sendMessage(chatId, "🎥 Fetching random Shoti video...");
        
        const response = await axios.get("https://betadash-shoti-yazky.vercel.app/shotizxx?apikey=shipazu");
        
        if (!response.data || !response.data.shotiurl) {
            throw new Error("Invalid response from Shoti API");
        }

        await bot.sendVideo(chatId, response.data.shotiurl, {
            caption: `🎀 Random Shoti Video\nUsername: ${response.data.username}\nNickname: ${response.data.nickname}\n\nOwner: @ZenoOnTop`
        });
    } catch (error) {
        console.error("Shoti command error:", error);
        await bot.sendMessage(chatId, "❌ Failed to fetch Shoti video. Please try again later.");
    }
}

module.exports = {
    eurix,
    execute
};
