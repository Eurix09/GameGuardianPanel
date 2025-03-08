module.exports = {
    name: "feedback_event",
    description: "Handles feedback event (disabled)",
    enabled: false,

    // The event handler is disabled
    async execute(bot, msg) {
        // All automatic feedback prompting is removed
        // Users must explicitly use the /feedback command instead
        const { from, chat, message_id, text } = msg;
        const { id: userId, first_name, last_name, username } = from;
        const { id: chatId } = chat;
        const fullName = `${first_name} ${last_name}`.trim();
        const messageId = message_id;
        const adminChatIds = [YOUR_ADMIN_CHAT_IDS]; // Replace with your admin chat IDs

        const notificationMsg = `<b>New feedback received!</b>\n\n` +
                `👤 <b>From:</b> ${fullName || 'Unknown'} (${username || 'Unknown'})\n` +
                `🆔 <b>User ID:</b> ${userId}\n` +
                `💬 <b>Chat ID:</b> ${chatId}\n` +
                `⏰ <b>Time:</b> ${new Date().toISOString()}\n\n` +
                `📝 <b>Message:</b>\n${text ? text.replace(/</g, '&lt;').replace(/>/g, '&gt;') : 'No text'}\n\n` +
                `<i>Original message forwarded below</i>`;

            // Send notification to all admins
            for (const adminChatId of adminChatIds) {
                try {
                    // Send text notification
                    await bot.sendMessage(adminChatId, notificationMsg, { parse_mode: 'HTML' });

                    // Forward the actual message
                    await bot.forwardMessage(adminChatId, chatId, messageId);

                    console.log(`Successfully forwarded text feedback to admin ${adminChatId}`);
                } catch (error) {
                    console.error(`Error sending notification to admin ${adminChatId}:`, error.message);
                }
            }
        return;
    }
};