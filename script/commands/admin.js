const fs = require('fs');
const path = require('path');

module.exports = {
  eurix: {
    name: "admin",
    description: "Manage bot administrators",
    permission: "admin"
  },

  async execute(bot, msg, args) {
    const chatId = msg.chat.id;
    const userId = msg.from.id;

    // Check if user is admin
    const configPath = path.join(__dirname, '../../config.json');
    let config;

    try {
      config = require(configPath);
      if (!config.admin || !config.admin.includes(userId.toString())) {
        return await bot.sendMessage(chatId, "❌ You don't have permission to use this command.");
      }
    } catch (error) {
      console.error('Error loading config:', error);
      return await bot.sendMessage(chatId, "❌ Error loading configuration.");
    }

    if (!args || args.length < 1) {
      return await bot.sendMessage(chatId, "❓ Usage:\n/admin add <userId>\n/admin remove <userId>\n/admin list");
    }

    const action = args[0].toLowerCase();

    switch (action) {
      case 'add':
        return await handleAddAdmin(bot, msg, args, config, configPath);
      case 'remove':
        return await handleRemoveAdmin(bot, msg, args, config, configPath);
      case 'list':
        return await handleListAdmins(bot, msg, config);
      default:
        return await bot.sendMessage(chatId, "❓ Unknown action. Use add, remove, or list.");
    }
  }
};

async function handleAddAdmin(bot, msg, args, config, configPath) {
  const chatId = msg.chat.id;

  if (args.length < 2) {
    return await bot.sendMessage(chatId, "❓ Usage: /admin add <userId>");
  }

  let targetId = args[1];

  if (isNaN(targetId)) {
    return await bot.sendMessage(chatId, "⚠️ Invalid user ID. Please enter a numeric user ID.");
  }

  // Ensure admin array exists
  if (!config.admin) {
    config.admin = [];
  }

  // Check if already admin
  if (config.admin.includes(targetId.toString())) {
    return await bot.sendMessage(chatId, `⚠️ User ID ${targetId} is already an admin.`);
  }

  // Add to admin list
  config.admin.push(targetId.toString());

  try {
    // Save updated config
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
    await bot.sendMessage(chatId, `✅ Added user ID ${targetId} to administrators.`);
  } catch (error) {
    console.error('Error saving config:', error);
    await bot.sendMessage(chatId, "❌ Error updating administrators list.");
  }
}

async function handleRemoveAdmin(bot, msg, args, config, configPath) {
  const chatId = msg.chat.id;

  if (args.length < 2) {
    return await bot.sendMessage(chatId, "❓ Usage: /admin remove <userId>");
  }

  let targetId = args[1];

  if (isNaN(targetId)) {
    return await bot.sendMessage(chatId, "⚠️ Invalid user ID. Please enter a numeric user ID.");
  }

  // Ensure admin array exists
  if (!config.admin || !config.admin.includes(targetId.toString())) {
    return await bot.sendMessage(chatId, `⚠️ User ID ${targetId} is not an admin.`);
  }

  // Remove from admin list
  config.admin = config.admin.filter(id => id !== targetId.toString());

  try {
    // Save updated config
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
    await bot.sendMessage(chatId, `✅ Removed user ID ${targetId} from administrators.`);
  } catch (error) {
    console.error('Error saving config:', error);
    await bot.sendMessage(chatId, "❌ Error updating administrators list.");
  }
}

async function handleListAdmins(bot, msg, config) {
  const chatId = msg.chat.id;

  if (!config.admin || config.admin.length === 0) {
    return await bot.sendMessage(chatId, "ℹ️ No administrators found.");
  }

  let message = "👑 *Administrators List*\n\n";

  for (const adminId of config.admin) {
    try {
      const user = await bot.getChat(adminId);
      const username = user.username ? `@${user.username}` : `\`${adminId}\``;
      message += `- ${username} (${adminId})\n`;
    } catch (error) {
      console.error(`Error fetching user ${adminId}:`, error);
      message += `- \`${adminId}\`\n`;
    }
  }

  await bot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
}