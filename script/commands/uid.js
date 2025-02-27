
const eurix = {
    name: "uid",
    description: "Get the user ID of a user"
};

async function execute(bot, msg, args) {
    const chatId = msg.chat.id;
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
