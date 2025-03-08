
const axios = require("axios");

module.exports = {
  eurix: {
    name: "ai",
    description: "Ask AI anything",
    permission: "all",
  },

  async execute(bot, msg, args) {
    const chatId = msg.chat.id;
    
    if (!args.length) {
      return bot.sendMessage(chatId, "⚠️ Please provide a question.\n\nUsage: /ai [your question]");
    }
    
    const question = args.join(" ");
    
    try {
      await bot.sendMessage(chatId, "🧠 Thinking...");
      
      const response = await axios.get(`https://betadash-api-swordslush.vercel.app/gpt4?ask=${encodeURIComponent(question)}`, {
        timeout: 60000 // 60 seconds timeout
      });
      
      if (response.data && response.data.content) {
        const answer = response.data.content;
        await bot.sendMessage(chatId, answer, { parse_mode: 'Markdown' });
      } else {
        throw new Error("Invalid API response format");
      }
    } catch (error) {
      console.error("AI command error:", error);
      await bot.sendMessage(
        chatId, 
        "❌ Sorry, I couldn't process your request right now.\n\nPlease try again later or contact @ZenoOnTop for assistance."
      );
    }
  }
};
