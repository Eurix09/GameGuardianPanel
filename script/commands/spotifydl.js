
const axios = require("axios");
const fs = require("fs");
const path = require("path");

module.exports = {
  eurix: {
    name: "spotify",
    permission: "all",
    description: "Download a song from Spotify"
  },

  execute: async function (bot, msg, args) {
    try {
      const chatId = msg.chat.id;
      const query = args.join(" ");
      
      if (!query) {
        return bot.sendMessage(chatId, "Please provide a Spotify URL\nUsage: the/spotify [spotify_url]");
      }

      // Send loading message
      const loadingMsg = await bot.sendMessage(chatId, "Downloading...");

      // Fetch metadata from the API
      const metadataResponse = await axios.post('https://spotydown.media/api/get-metadata', {
        url: query
      }, {
        headers: { 'Content-Type': 'application/json' }
      });

      // Fetch download URL
      const downloadResponse = await axios.post('https://spotydown.media/api/download-track', {
        url: query
      }, {
        headers: { 'Content-Type': 'application/json' }
      });

      const trackData = metadataResponse.data.apiResponse.data[0];
      const { album, artist, name: title, cover_url: coverImage } = trackData;
      const mp3Url = downloadResponse.data.file_url;

      // Define paths for saving the files
      const cacheDir = path.join(__dirname, "../../cache");
      const mp3Path = path.join(cacheDir, `spotify_${Date.now()}.mp3`);
      const imgPath = path.join(cacheDir, `spotify_${Date.now()}.jpg`);

      // Ensure the cache directory exists
      if (!fs.existsSync(cacheDir)) {
        fs.mkdirSync(cacheDir, { recursive: true });
      }

      // Fetch and save the mp3 file
      const mp3 = await axios.get(mp3Url, { responseType: "arraybuffer" });
      fs.writeFileSync(mp3Path, Buffer.from(mp3.data));

      // Fetch and save the image
      const img = await axios.get(coverImage, { responseType: "arraybuffer" });
      fs.writeFileSync(imgPath, Buffer.from(img.data));

      // Update status message
      await bot.editMessageText("✅ Download complete! Sending your files...", {
        chat_id: chatId,
        message_id: loadingMsg.message_id
      });

      // Send the album cover
      await bot.sendPhoto(chatId, imgPath, {
        caption: `SuccesFully Downloaded\n🎵 *${title}*\n👤 Artist: ${artist}\n💿 Album: ${album}\nOwner: @ZenoOnTop`,
        parse_mode: 'Markdown'
      });

      // Send the audio file
      await bot.sendAudio(chatId, mp3Path, {
        title: title,
        performer: artist
      });

      // Clean up the files
      setTimeout(() => {
        try {
          if (fs.existsSync(mp3Path)) fs.unlinkSync(mp3Path);
          if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
        } catch (err) {
          console.error("Error cleaning up files:", err);
        }
      }, 5000);

    } catch (error) {
      console.error("Spotify Download Error:", error.message);
      bot.sendMessage(msg.chat.id, `❌ An error occurred: ${error.message}`);
    }
  }
};
    
