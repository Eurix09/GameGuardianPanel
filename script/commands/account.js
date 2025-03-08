
const fs = require('fs');
const path = require('path');

module.exports = {
  eurix: {
    name: "account",
    description: "Show account and key list",
    permission: "admin"
  },

  async execute(bot, msg, args) {
    const chatId = msg.chat.id;
    const userId = msg.from.id;
    
    // Check if user is admin
    const config = require('../../config.json');
    if (!config.admin || !config.admin.includes(userId.toString())) {
      return await bot.sendMessage(chatId, "❌ You don't have permission to use this command.");
    }

    try {
      // Read login users file
      const loginUserFile = path.join(__dirname, '../../LoginUser.json');
      if (!fs.existsSync(loginUserFile)) {
        return await bot.sendMessage(chatId, "❌ No accounts found. The user database does not exist.");
      }
      
      const users = JSON.parse(fs.readFileSync(loginUserFile, 'utf8'));
      const userCount = Object.keys(users).length;
      
      if (userCount === 0) {
        return await bot.sendMessage(chatId, "📋 *Account List*\n\nNo accounts found in the database.", { parse_mode: 'Markdown' });
      }
      
      // Create account list message with better formatting
      let accountMsg = `📋 *Account List (${userCount} accounts)*\n\n`;
      
      Object.keys(users).forEach((username, index) => {
        const user = users[username];
        const regDate = user.registrationDate ? new Date(user.registrationDate).toLocaleDateString() : 'Unknown';
        
        accountMsg += `*${index + 1}. ${username}*\n`;
        accountMsg += `🔑 Password: \`${user.password || 'Not set'}\`\n`;
        accountMsg += `📅 Registered: ${regDate}\n\n`;
      });

      // Send account list
      await bot.sendMessage(chatId, accountMsg, { 
        parse_mode: 'Markdown',
        disable_web_page_preview: true
      });

      // Send each user's key file
      const userPanelDir = path.join(__dirname, '../../USERPANEL');
      if (!fs.existsSync(userPanelDir)) {
        return await bot.sendMessage(chatId, "⚠️ USERPANEL directory not found. Cannot send key files.");
      }
      
      // Check if there are key files to send
      let keyFilesFound = false;
      
      for (const username of Object.keys(users)) {
        const keyFile = path.join(userPanelDir, `${username}.json`);
        if (fs.existsSync(keyFile)) {
          keyFilesFound = true;
          try {
            // Send file with caption
            await bot.sendDocument(chatId, keyFile, {
              caption: `🔑 Keys for user: ${username}`
            });
          } catch (fileError) {
            console.error(`Error sending key file for ${username}:`, fileError);
            await bot.sendMessage(chatId, `⚠️ Could not send key file for user: ${username}`);
          }
        }
      }
      
      if (!keyFilesFound) {
        await bot.sendMessage(chatId, "ℹ️ No key files found for any users.");
      }
    } catch (error) {
      console.error('Error in account command:', error);
      await bot.sendMessage(chatId, "❌ Error occurred while fetching account information: " + error.message);
    }
  }
};
