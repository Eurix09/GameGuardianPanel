const axios = require('axios');
const fs = require('fs');
const path = require('path');

module.exports = {
  eurix: {
    name: "tiktokdl",
    description: "tiktokdl <url>",
    permission: "all",
  },

  execute: async function (bot, msg, args) {
    const chatId = msg.chat.id;

    if (!args.length) {
      return bot.sendMessage(chatId, "❌ Please provide a TikTok URL.");
    }

    const link = args[0];

    try {
      // Send loading message
      const loadingMsg = await bot.sendMessage(chatId, "⏳ Processing your TikTok link...");

      // Create cache directory if it doesn't exist
      const cacheDir = path.join(__dirname, "../../cache");
      if (!fs.existsSync(cacheDir)) {
        fs.mkdirSync(cacheDir, { recursive: true });
      }

      // Fetch TikTok data
      const response = await axios.get(`https://tikwm.com/api?url=${encodeURIComponent(link)}`);

      if (!response.data || !response.data.data) {
        throw new Error("Invalid response from TikTok API.");
      }

      const data = response.data.data;
      const username = data.author?.unique_id || "Unknown";
      const nickname = data.author?.nickname || "Unknown";
      const title = data.title || "No title";
      const images = data.images || [];
      const video = data.play || null;

      const caption = `✅ Downloaded Successfully\n\n👤 Username: @${username}\n📝 Nickname: ${nickname}\n📌 Title: ${title}`;

      // Edit loading message to notify processing is done
      await bot.editMessageText("✅ Download complete! Sending content...", {
        chat_id: chatId,
        message_id: loadingMsg.message_id,
      });

      // Process images if available
      if (images.length > 0) {
        try {
          if (images.length > 1) {
            // Multiple images
            const mediaGroup = [];
            const imagePaths = [];

            for (let i = 0; i < images.length; i++) {
              const imagePath = path.join(cacheDir, `tiktok_image_${i}.jpg`);
              imagePaths.push(imagePath);
              const imgResponse = await axios.get(images[i], { responseType: "arraybuffer" });
              fs.writeFileSync(imagePath, Buffer.from(imgResponse.data));

              mediaGroup.push({
                type: 'photo',
                media: fs.createReadStream(imagePath),
                caption: i === 0 ? caption : undefined,
              });
            }

            // Send images
            await bot.sendMediaGroup(chatId, mediaGroup);

            // Cleanup
            imagePaths.forEach((p) => fs.existsSync(p) && fs.unlinkSync(p));
          } else {
            // Single image
            const imagePath = path.join(cacheDir, `tiktok_image_0.jpg`);
            const imgResponse = await axios.get(images[0], { responseType: "arraybuffer" });
            fs.writeFileSync(imagePath, Buffer.from(imgResponse.data));

            await bot.sendPhoto(chatId, fs.createReadStream(imagePath), { caption });

            // Cleanup
            fs.unlinkSync(imagePath);
          }
        } catch (imgError) {
          console.error("Error processing TikTok images:", imgError);
          await bot.sendMessage(chatId, "❌ Failed to process images from this TikTok.");
        }
      } 
      // Process video if available
      else if (video) {
        try {
          const videoPath = path.join(cacheDir, "tiktok.mp4");
          const videoResponse = await axios.get(video, { responseType: "arraybuffer" });
          fs.writeFileSync(videoPath, Buffer.from(videoResponse.data));

          // Send video
          await bot.sendVideo(chatId, fs.createReadStream(videoPath), { caption });

          // Cleanup
          fs.unlinkSync(videoPath);
        } catch (videoError) {
          console.error("Error processing TikTok video:", videoError);
          await bot.sendMessage(chatId, "❌ Failed to process video from this TikTok.");
        }
      } else {
        await bot.sendMessage(chatId, "❌ No media content found in this TikTok.");
      }

      // Delete loading message
      await bot.deleteMessage(chatId, loadingMsg.message_id);
    } catch (error) {
      console.error("TikTok download error:", error.message);
      await bot.sendMessage(chatId, `❌ Error: ${error.message || "Failed to download TikTok content"}`);
    }
  }
};