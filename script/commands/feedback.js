const feedbackSessions = new Map();

module.exports = {
    eurix: {
        name: "feedback",
        description: "Send feedback to the admin team"
    },

    feedbackSessions,

    async execute(bot, msg, args) {
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
                } catch (error) {
                    console.error(`Error sending notification to admin ${adminChatId}:`, error);
                }
            }

            // Confirm receipt to the user
            await bot.sendMessage(chatId, "✅ Your feedback has been sent to the admin team. Thank you!");

            // End the feedback session
            feedbackSessions.delete(userId);
            return;
        }

        // Start a new feedback session
        feedbackSessions.set(userId, true);

        await bot.sendMessage(chatId, 
            "📝 <b>Feedback Mode Started</b>\n\n" +
            "Please type your feedback message now. Photos and videos are also accepted.\n\n" +
            "Type /cancel to exit feedback mode.",
            { parse_mode: 'HTML' }
        );
    }
};
const fs = require('fs');
const path = require('path');
const axios = require('axios');

module.exports = {
    eurix: {
        name: "feedback",
        description: "Send feedback to the admin team",
        usage: "/feedback [your message]",
        permission: "all"
    },

    // Store active feedback sessions
    feedbackSessions: new Map(),

    async execute(bot, msg, args) {
        const chatId = msg.chat.id;
        const userId = msg.from.id;
        const messageId = msg.message_id;
        
        // Command to cancel feedback mode
        if (msg.text === "/cancel") {
            if (this.feedbackSessions.has(userId)) {
                this.feedbackSessions.delete(userId);
                await bot.sendMessage(chatId, "❌ Feedback session canceled.", {
                    reply_markup: {
                        remove_keyboard: true
                    }
                });
            } else {
                await bot.sendMessage(chatId, "You don't have an active feedback session.");
            }
            return;
        }

        // Start a new feedback session if user sends the command
        if (msg.text && msg.text.startsWith("/feedback")) {
            // User is starting feedback mode
            this.feedbackSessions.set(userId, {
                startTime: Date.now(),
                status: 'waiting'
            });
            
            await bot.sendMessage(chatId, 
                "📝 <b>Feedback Mode Activated</b>\n\n" +
                "Please send your feedback with any of the following:\n" +
                "• Text message\n" +
                "• Photos (with optional caption)\n" +
                "• Videos (with optional caption)\n" +
                "• APK files (with optional caption)\n\n" +
                "Type /cancel to exit feedback mode.",
                {
                    parse_mode: "HTML",
                    reply_markup: {
                        keyboard: [
                            [{ text: "/cancel" }]
                        ],
                        resize_keyboard: true
                    }
                }
            );
            return;
        }

        // Handle ongoing feedback session
        if (this.feedbackSessions.has(userId)) {
            const config = require('../../config');
            const adminChatIds = config.admin || [];
            
            // Extract user information
            const firstName = msg.from.first_name || "";
            const lastName = msg.from.last_name || "";
            const fullName = `${firstName} ${lastName}`.trim();
            const username = msg.from.username ? `@${msg.from.username}` : "No username";
            
            // Get caption or text message
            const caption = msg.caption || msg.text || "";
            
            // Handle different types of media
            if (msg.photo && msg.photo.length > 0) {
                // Photo feedback processing
                await this.processPhotoFeedback(bot, msg, adminChatIds, userId, chatId, messageId, fullName, username, caption);
            } 
            else if (msg.video) {
                // Video feedback processing
                await this.processVideoFeedback(bot, msg, adminChatIds, userId, chatId, messageId, fullName, username, caption);
            }
            else if (msg.document) {
                // Document (potentially APK) feedback processing
                await this.processDocumentFeedback(bot, msg, adminChatIds, userId, chatId, messageId, fullName, username, caption);
            }
            else if (msg.text) {
                // Text feedback processing
                await this.processTextFeedback(bot, msg, adminChatIds, userId, chatId, messageId, fullName, username);
            }
            
            // End the feedback session after processing
            this.feedbackSessions.delete(userId);
            
            // Remove keyboard
            await bot.sendMessage(chatId, "✅ Thank you for your feedback! Your message has been sent to our team.", {
                reply_markup: {
                    remove_keyboard: true
                }
            });
        }
    },
    
    async processPhotoFeedback(bot, msg, adminChatIds, userId, chatId, messageId, fullName, username, caption) {
        try {
            console.log(`Received photo feedback from ${fullName} (${username})`);
            
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
        } catch (error) {
            console.error('Error in photo feedback processing:', error);
        }
    },
    
    async processVideoFeedback(bot, msg, adminChatIds, userId, chatId, messageId, fullName, username, caption) {
        try {
            console.log(`Received video feedback from ${fullName} (${username})`);
            
            // Create notification for admins
            const notificationMsg = `🎬 <b>New Video Feedback Received!</b>\n\n` +
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
                    
                    console.log(`Successfully forwarded video feedback to admin ${adminChatId}`);
                } catch (error) {
                    console.error(`Error sending notification to admin ${adminChatId}:`, error.message);
                }
            }
        } catch (error) {
            console.error('Error in video feedback processing:', error);
        }
    },
    
    async processDocumentFeedback(bot, msg, adminChatIds, userId, chatId, messageId, fullName, username, caption) {
        try {
            const fileName = msg.document.file_name || "unknown_file";
            const fileSize = msg.document.file_size || 0;
            const isApk = fileName.toLowerCase().endsWith('.apk');
            const fileType = isApk ? "APK" : "document";
            
            console.log(`Received ${fileType} feedback from ${fullName} (${username}): ${fileName} (${fileSize} bytes)`);
            
            // Create notification for admins
            const notificationMsg = `📁 <b>New ${fileType.toUpperCase()} Feedback Received!</b>\n\n` +
                `👤 <b>From:</b> ${fullName} (${username})\n` +
                `🆔 <b>User ID:</b> ${userId}\n` +
                `💬 <b>Chat ID:</b> ${chatId}\n` +
                `📄 <b>File:</b> ${fileName}\n` +
                `📏 <b>Size:</b> ${(fileSize / 1024).toFixed(2)} KB\n` +
                `📝 <b>Caption:</b> ${caption}\n` +
                `⏰ <b>Time:</b> ${new Date().toISOString()}\n\n` +
                `<i>Forwarding ${fileType} to admins...</i>`;
                
            // Send notification to all admins
            for (const adminChatId of adminChatIds) {
                try {
                    // Send text notification
                    await bot.sendMessage(adminChatId, notificationMsg, { parse_mode: 'HTML' });
                    
                    // Forward the actual document
                    await bot.forwardMessage(adminChatId, chatId, messageId);
                    
                    console.log(`Successfully forwarded ${fileType} feedback to admin ${adminChatId}`);
                } catch (error) {
                    console.error(`Error sending notification to admin ${adminChatId}:`, error.message);
                }
            }
        } catch (error) {
            console.error('Error in document feedback processing:', error);
        }
    },
    
    async processTextFeedback(bot, msg, adminChatIds, userId, chatId, messageId, fullName, username) {
        try {
            const text = msg.text;
            console.log(`Received text feedback from ${fullName} (${username}): ${text.substring(0, 50)}...`);
            
            // Create notification for admins
            const notificationMsg = `💬 <b>New Text Feedback Received!</b>\n\n` +
                `👤 <b>From:</b> ${fullName} (${username})\n` +
                `🆔 <b>User ID:</b> ${userId}\n` +
                `💬 <b>Chat ID:</b> ${chatId}\n` +
                `⏰ <b>Time:</b> ${new Date().toISOString()}\n\n` +
                `📝 <b>Message:</b>\n${text}\n\n` +
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
        } catch (error) {
            console.error('Error in text feedback processing:', error);
        }
    }
};
