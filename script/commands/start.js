const eurix = {
    name: "start",
    description: "Get started with bot commands"
};

async function execute(bot, msg) {
    const chatId = msg.chat.id;
    const firstName = msg.from.first_name;

    try {
        const welcomeMessage = `👋 Welcome ${firstName}!\n\n` +
                             `🤖 I am your Zeno Assistant\n\n` +
                             `📚 Available Commands:\n\n` +
                             `/help - Show all commands\n` +
                             `/start - Start the bot\n\n` +
                             `Need help? Contact @ZenoOnTop`;

        await bot.sendMessage(chatId, welcomeMessage);
    } catch (error) {
        console.error("Start command error:", error);
        await bot.sendMessage(chatId, "❌ An error occurred while processing your request.");
    }
}

module.exports = {
    eurix,
    execute
};