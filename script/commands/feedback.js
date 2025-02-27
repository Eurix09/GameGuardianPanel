
const feedbackSessions = new Map();

const eurix = {
    name: "feedback",
    permission: "all",
    description: "Send feedback to the admin team"
};

async function execute(bot, msg, args) {
    const chatId = msg.chat.id;
    const userId = msg.from.id;
    
    // If user is canceling feedback
    if (msg.text?.toLowerCase() === '/cancel') {
        if (feedbackSessions.has(userId)) {
            feedbackSessions.delete(userId);
            await bot.sendMessage(chatId, "❌ Feedback canceled.");
        }
        return;
    }
    
    // Check if the user already has an active feedback session
    if (feedbackSessions.has(userId)) {
        // This is an actual feedback message with content
        const feedbackText = msg.text;
        const config = require('../../config');
        const adminChatIds = config.admin || [];
        
        // Create the notification message for admins
        const username = msg.from?.username ? '@' + msg.from.username : 'Unknown';
        const firstName = msg.from?.first_name || 'Unknown';
        const lastName = msg.from?.last_name || '';
        const fullName = `${firstName} ${lastName}`.trim();
        
        const notificationMsg = `💬 <b>New Feedback Received!</b>\n\n` +
          `👤 <b>From:</b> ${fullName} (${username})\n` +
          `🆔 <b>User ID:</b> ${userId}\n` +
          `💬 <b>Chat ID:</b> ${chatId}\n` +
          `📝 <b>Message:</b> ${feedbackText}\n` +
          `⏰ <b>Time:</b> ${new Date().toISOString()}`;
          
        // Send notification to all admins
        for (const adminChatId of adminChatIds) {
            try {
                await bot.sendMessage(adminChatId, notificationMsg, { parse_mode: 'HTML' });
                console.log(`Successfully forwarded feedback to admin ${adminChatId}`);
            } catch (error) {
                console.error(`Error sending notification to admin ${adminChatId}:`, error.message);
            }
        }
        
        // Send confirmation to the user
        await bot.sendMessage(chatId, "✅ Thank you for your feedback! We'll review it as soon as possible.");
        feedbackSessions.delete(userId);
        return;
    }
    
    // Starting a new feedback session
    feedbackSessions.set(userId, true);
    
    await bot.sendMessage(
        chatId, 
        "📝 Please reply with your feedback message. Your feedback is valuable to us!\n\nType /cancel to cancel."
    );
}

module.exports = {
    eurix,
    execute,
    feedbackSessions
};
