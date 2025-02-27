const eurix = {
    name: "unsend",
    description: "Delete a message by replying to it"
};

async function execute(bot, msg) {
    try {
        // Check if the command is a reply to a message
        if (!msg.reply_to_message) {
            await bot.sendMessage(msg.chat.id, "⚠️ Please reply to a message you want to delete.");
            return;
        }

        // Delete the replied message
        await bot.deleteMessage(msg.chat.id, msg.reply_to_message.message_id);

        // Delete the command message itself
        await bot.deleteMessage(msg.chat.id, msg.message_id);

    } catch (error) {
        console.error('Error in unsend command:', error);

        // Check if it's a permission error
        if (error.response?.description?.includes('delete')) {
            await bot.sendMessage(msg.chat.id, "❌ I don't have permission to delete that message.");
            return;
        }

        // Generic error notification
        await bot.sendMessage(msg.chat.id, "❌ Failed to delete the message.");
    }
}

module.exports = {
    eurix,
    execute
};