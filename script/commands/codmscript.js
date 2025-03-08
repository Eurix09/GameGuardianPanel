const fs = require('fs');
const path = require('path');
const axios = require('axios');

module.exports = {
  eurix: {
    name: 'codmscript',
    permission: 'admin',
    description: 'Upload CODM Lua scripts',
    usage: '/codmscript | /codmscript add'
  },

  activeUploaders: new Map(),

  execute: async function(bot, msg, args) {
    try {
      // Check if a subcommand was provided
      if (args.length > 0 && args[0] === 'add') {
        // Begin the upload process by sending instructions
        await bot.sendMessage(msg.chat.id, "Please send me your Lua script file (.lua).\n\n/cancel");

        // Add user to active uploaders
        this.activeUploaders.set(msg.from.id, {
          chatId: msg.chat.id,
          step: 'waiting_for_file',
          timestamp: Date.now()
        });

        // Set up listener for file uploads
        bot.on('message', async (uploadMsg) => {
          // Check if this user is in active uploaders and they sent a document
          const uploader = this.activeUploaders.get(uploadMsg.from.id);
          if (!uploader || uploader.step !== 'waiting_for_file') return;

          // If user sends a text message instead of a file, check if it's a cancel command
          if (!uploadMsg.document && uploadMsg.text) {
            if (uploadMsg.text.toLowerCase() === '/cancel') {
              this.activeUploaders.delete(uploadMsg.from.id);
              return bot.sendMessage(uploadMsg.chat.id, "❌ CODM script upload cancelled.");
            }
            return bot.sendMessage(uploadMsg.chat.id, "Please send a .lua file, or type /cancel to abort.");
          }

          // Make sure they sent a file
          if (!uploadMsg.document) {
            return bot.sendMessage(uploadMsg.chat.id, "Please send a .lua file, or type /cancel to abort.");
          }

          // Check file extension
          const fileName = uploadMsg.document.file_name;
          if (!fileName || !fileName.toLowerCase().endsWith('.lua')) {
            return bot.sendMessage(uploadMsg.chat.id, "Only .lua files are accepted. Please send a valid Lua script, or type /cancel to abort.");
          }

          try {
            // Let user know we're processing
            await bot.sendMessage(uploadMsg.chat.id, "⏳ Processing your Lua script...");

            // Get file path from Telegram
            const fileInfo = await bot.getFile(uploadMsg.document.file_id);
            const fileUrl = `https://api.telegram.org/file/bot${bot.token}/${fileInfo.file_path}`;

            // Download the file
            const response = await axios.get(fileUrl, { responseType: 'arraybuffer' });
            const luaContent = Buffer.from(response.data);

            // Save to ZenoOnTopVip.lua
            const filePath = path.join(__dirname, '../../ZenoOnTopVip.lua');
            fs.writeFileSync(filePath, luaContent);

            // Basic validation of Lua content
            const warnings = validateLuaFile(luaContent.toString('utf8'));

            // Success message
            let message = `✅ CODM script uploaded successfully!\n\n📁 File: ${fileName}\n📦 Size: ${(uploadMsg.document.file_size / 1024).toFixed(2)} KB`;

            if (warnings.length > 0) {
              message += "\n\n⚠️ Warnings:\n" + warnings.join('\n');
            }

            await bot.sendMessage(uploadMsg.chat.id, message);

            // Clean up
            this.activeUploaders.delete(msg.from.id);

            // Return to avoid processing this message further
            return;
          } catch (error) {
            console.error("Error processing Lua file:", error);
            await bot.sendMessage(uploadMsg.chat.id, "❌ Error processing your file: " + error.message);
            this.activeUploaders.delete(msg.from.id);
            return;
          }
        });
      } else {
        // Default behavior - just send the Lua file to the user
        const luaFilePath = path.join(__dirname, '../../ZenoOnTopVip.lua');

        // Check if the Lua file exists
        if (!fs.existsSync(luaFilePath)) {
          return bot.sendMessage(msg.chat.id, "❌ The CODM script file is not available. Please contact the administrator.");
        }

        const caption = `✨ CODM Free VIP Cheat ✨

🆓 This is free, so don't abuse it!

🔑 Password: FreeForEveryone

💬 Feedback here: @Eurix_bot or @ZenoOnTop

📢 Join my main channel: https://t.me/zenoofficial_09
💬 Join the discussion: https://t.me/ZenoDiscussionCodm

⚠️ No feedback, no updates!`;

        try {
          // Send the file with caption
          await bot.sendDocument(msg.chat.id, luaFilePath, {
            caption: caption,
            parse_mode: 'HTML'
          });

          await bot.sendMessage(msg.chat.id, "✅ Remember to follow the instructions carefully. Enjoy!");
        } catch (error) {
          console.error("Error sending CODM script:", error);
          await bot.sendMessage(msg.chat.id, "❌ An error occurred while sending the script. Please try again later.");
        }
      }
    } catch (error) {
      console.error("CODM script command error:", error);
      bot.sendMessage(msg.chat.id, "❌ An error occurred while processing your request.");
    }
  }
};

// Function to validate Lua file content
function validateLuaFile(content) {
  const warnings = [];

  // Check for unbalanced parentheses
  let openParens = 0;
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '(') openParens++;
    if (content[i] === ')') openParens--;
  }
  if (openParens !== 0) warnings.push("⚠️ Unbalanced parentheses detected");

  // Check for unbalanced curly braces
  let openBraces = 0;
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '{') openBraces++;
    if (content[i] === '}') openBraces--;
  }
  if (openBraces !== 0) warnings.push("⚠️ Unbalanced curly braces detected");

  // Check for unclosed strings
  let inString = false;
  let stringDelimiter = '';
  for (let i = 0; i < content.length; i++) {
    const char = content[i];
    if (!inString && (char === '"' || char === "'")) {
      inString = true;
      stringDelimiter = char;
    } else if (inString && char === stringDelimiter && content[i-1] !== '\\') {
      inString = false;
    }
  }
  if (inString) warnings.push("⚠️ Unclosed string detected");

  // Check if the file contains basic Lua keywords
  const containsLuaKeywords = /\b(function|end|local|if|then|else|for|while|do|return)\b/.test(content);
  if (!containsLuaKeywords) {
    warnings.push("⚠️ File doesn't appear to contain Lua code");
  }

  return warnings;
}