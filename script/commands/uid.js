 
const eurix = {
    name: "uid",
    description: "Get the user ID of a user or all users in the chat"
};

async function execute(bot, msg, args) {
    const chatId = msg.chat.id;

    // Check if user wants to see all user IDs
    if (args.length > 0 && args[0].toLowerCase() === 'all') {
        try {
            // Get chat members for groups and supergroups
            if (msg.chat.type === 'group' || msg.chat.type === 'supergroup' || msg.chat.type === 'channel') {
                const memberCount = await bot.getChatMemberCount(chatId);
                let userListMessage = `👥 *User List in This Chat (${memberCount} members)*\n\n`;

                // First list admins
                const chatAdmins = await bot.getChatAdministrators(chatId);

                userListMessage += `*Admins:*\n`;
                for (const member of chatAdmins) {
                    const user = member.user;
                    const role = member.status === 'creator' ? '👑 Creator' : '⭐ Admin';
                    userListMessage += `${role}\n`;
                    userListMessage += `👤 ${user.first_name || ''} ${user.last_name || ''}\n`;
                    userListMessage += `🆔 \`${user.id}\`\n`;
                    userListMessage += `👥 ${user.username ? '@' + user.username : 'No username'}\n\n`;
                }

                // Try to get recent messages to identify non-admin members
                userListMessage += `\n*Other Members (Recent):*\n`;

                try {
                    // Get recent chat messages to identify participants
                    const updates = await bot.getUpdates({
                        chat_id: chatId,
                        limit: 100
                    });

                    // Create a Map to store unique users
                    const uniqueUsers = new Map();

                    // Extract users from updates
                    for (const update of updates) {
                        if (update.message && update.message.from && 
                            update.message.chat && update.message.chat.id === chatId) {

                            const user = update.message.from;
                            // Only add if not already in the map and not an admin
                            if (!uniqueUsers.has(user.id) && 
                                !chatAdmins.some(admin => admin.user.id === user.id)) {
                                uniqueUsers.set(user.id, user);
                            }
                        }
                    }

                    // Display unique users found in recent messages
                    for (const [id, user] of uniqueUsers) {
                        userListMessage += `👤 ${user.first_name || ''} ${user.last_name || ''}\n`;
                        userListMessage += `🆔 \`${user.id}\`\n`;
                        userListMessage += `👥 ${user.username ? '@' + user.username : 'No username'}\n\n`;
                    }

                    if (uniqueUsers.size === 0) {
                        userListMessage += `No additional members found in recent messages.\n`;
                    }

                } catch (memberError) {
                    console.error('Error fetching members:', memberError);
                    userListMessage += `Could not retrieve additional members.\n`;
                }

                userListMessage += `\n*Note:* This command can only show admins and users who recently sent messages in the chat. For private chat with the bot, use /uid to see your own ID.`;

                await bot.sendMessage(chatId, userListMessage, {
                    parse_mode: 'Markdown'
                });
            } else {
                await bot.sendMessage(chatId, "❌ The 'all' option only works in group chats.");
            }
            return;
        } catch (error) {
            console.error('Error fetching all users:', error);
            await bot.sendMessage(chatId, '❌ An error occurred while retrieving user list.');
            return;
        }
    }

    // Regular uid command for individual user
    const targetUser = msg.from;

    try {
        let userPhotos;

        // Fetch user profile photos
        try {
            userPhotos = await bot.getUserProfilePhotos(targetUser.id);
        } catch (photoError) {
            console.error('Profile photo error:', photoError);
            userPhotos = null;
        }

        // Format user details
        const userDetails = `
📋 *User Information*

👤 Name: ${targetUser.first_name || ''} ${targetUser.last_name || ''}
🆔 User ID: \`${targetUser.id}\`
👥 Username: ${targetUser.username ? '@' + targetUser.username : 'No username'}

🌐 *Chat Details:*
💬 Chat ID: \`${msg.chat.id}\`
📊 Chat Type: ${msg.chat.type}
`;

        // Send either a photo with details or just text
        if (userPhotos && userPhotos.total_count > 0) {
            await bot.sendPhoto(chatId, userPhotos.photos[0][0].file_id, {
                caption: userDetails,
                parse_mode: 'Markdown'
            });
        } else {
            await bot.sendMessage(chatId, userDetails, {
                parse_mode: 'Markdown'
            });
        }

    } catch (error) {
        console.error('ID Command Error:', error);
        await bot.sendMessage(chatId, '❌ An error occurred while retrieving ID information.');
    }
}

module.exports = {
    eurix,
    execute
};