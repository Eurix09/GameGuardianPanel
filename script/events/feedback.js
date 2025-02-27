
module.exports = {
  name: 'feedback',
  execute: async (bot, msg) => {
    try {
      const config = require('../../config');
      const adminChatIds = config.admin || [];

      // Extract common user info
      const username = msg.from?.username ? '@' + msg.from.username : 'Unknown';
      const firstName = msg.from?.first_name || 'Unknown';
      const lastName = msg.from?.last_name || '';
      const fullName = `${firstName} ${lastName}`.trim();
      const chatId = msg.chat.id;
      const userId = msg.from?.id || 'Unknown';
      const messageId = msg.message_id;
      const caption = msg.caption || 'No caption';
      const text = msg.text || 'No text';
      
      // Make sure there are admin chat IDs to send to
      if (adminChatIds.length === 0) {
        console.error('No admin chat IDs configured. Please check your config.json file.');
        return;
      }

      // Check if message contains video
      if (msg.video) {
        console.log(`Received video feedback from ${fullName} (${username})`);

        // Create notification for admins
        const notificationMsg = `📹 <b>New Video Feedback Received!</b>\n\n` +
          `👤 <b>From:</b> ${fullName} (${username})\n` +
          `🆔 <b>User ID:</b> ${userId}\n` +
          `💬 <b>Chat ID:</b> ${chatId}\n` +
          `📝 <b>Caption:</b> ${caption}\n` +
          `⏰ <b>Time:</b> ${new Date().toISOString()}\n\n` +
          `<i>Forwarding video to admins...</i>`;

        // Send notification to all admins
        for (const adminChatId of adminChatIds) {
          try {
            // Send text notification
            await bot.sendMessage(adminChatId, notificationMsg, { parse_mode: 'HTML' });

            // Forward the actual video
            await bot.forwardMessage(adminChatId, chatId, messageId);

            console.log(`Successfully forwarded feedback to admin ${adminChatId}`);
          } catch (error) {
            console.error(`Error sending notification to admin ${adminChatId}:`, error.message);
          }
        }

        // Send confirmation to the user
        await bot.sendMessage(chatId, '✅ Thank you for your feedback! Your video has been sent to our team.');
      } 
      // Check if message contains photo
      else if (msg.photo && msg.photo.length > 0) {
        console.log(`Received photo feedback from ${fullName} (${username})`);
        
        // Get the highest quality photo (last item in the array)
        const photo = msg.photo[msg.photo.length - 1];
        
        // Create notification for admins
        const notificationMsg = `📸 <b>New Photo Feedback Received!</b>\n\n` +
          `👤 <b>From:</b> ${fullName} (${username})\n` +
          `🆔 <b>User ID:</b> ${userId}\n` +
          `💬 <b>Chat ID:</b> ${chatId}\n` +
          `📝 <b>Caption:</b> ${caption}\n` +
          `⏰ <b>Time:</b> ${new Date().toISOString()}\n\n` +
          `<i>Forwarding photo to admins...</i>`;

        // Send notification to all admins
        for (const adminChatId of adminChatIds) {
          try {
            // Send text notification
            await bot.sendMessage(adminChatId, notificationMsg, { parse_mode: 'HTML' });

            // Forward the actual photo
            await bot.forwardMessage(adminChatId, chatId, messageId);

            console.log(`Successfully forwarded photo feedback to admin ${adminChatId}`);
          } catch (error) {
            console.error(`Error sending notification to admin ${adminChatId}:`, error.message);
          }
        }

        // Send confirmation to the user
        await bot.sendMessage(chatId, '✅ Thank you for your feedback! Your photo has been sent to our team.');
      }
      // Handle text messages (if not from the /feedback command flow)
      else if (msg.text && !msg.text.startsWith('/')) {
        console.log(`Received text feedback from ${fullName} (${username})`);
        
        // Create notification for admins
        const notificationMsg = `💬 <b>New Text Feedback Received!</b>\n\n` +
          `👤 <b>From:</b> ${fullName} (${username})\n` +
          `🆔 <b>User ID:</b> ${userId}\n` +
          `💬 <b>Chat ID:</b> ${chatId}\n` +
          `📝 <b>Message:</b> ${text}\n` +
          `⏰ <b>Time:</b> ${new Date().toISOString()}`;

        // Send notification to all admins
        for (const adminChatId of adminChatIds) {
          try {
            // Send text notification
            await bot.sendMessage(adminChatId, notificationMsg, { parse_mode: 'HTML' });
            console.log(`Successfully forwarded text feedback to admin ${adminChatId}`);
          } catch (error) {
            console.error(`Error sending notification to admin ${adminChatId}:`, error.message);
          }
        }

        // Send confirmation to the user
        await bot.sendMessage(chatId, '✅ Thank you for your feedback! Your message has been sent to our team.');
      }
    } catch (error) {
      console.error('Error in feedback event handler:', error);
    }
  }
};
