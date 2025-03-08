
const eurix = {
    name: "pin",
    description: "Pin a message in the chat",
    usage: "/pin [reply to a message]",
    permission: "admin" // Only admins can use this command
};

async function execute(bot, msg) {
    const chatId = msg.chat.id;

    try {
        // Check if the command is a reply to a message
        if (!msg.reply_to_message) {
            await bot.sendMessage(chatId, "⚠️ Please reply to a message you want to pin.");
            return;
        }

        // Get the message_id of the replied message
        const messageId = msg.reply_to_message.message_id;

        // Try to pin the message
        await bot.pinChatMessage(chatId, messageId);

        // Send confirmation (optional - you can comment this out if you don't want a notification)
        await bot.sendMessage(chatId, "📌 Message pinned successfully!");

    } catch (error) {
        console.error('Error in pin command:', error);

        // Check if it's a permission error
        if (error.response?.description?.includes('pin')) {
            await bot.sendMessage(chatId, "❌ I don't have permission to pin messages in this chat.");
            return;
        }

        // Generic error notification
        await bot.sendMessage(chatId, "❌ Failed to pin the message. Make sure I have admin privileges in this group.");
    }
}

module.exports = {
    eurix,
    execute
};
