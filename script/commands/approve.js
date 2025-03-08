
const fs = require('fs');
const path = require('path');

module.exports = {
    eurix: {
        name: "approve",
        description: "Approve a device ID or ban/unban/remove a device",
        usage: "/approve [deviceId] or /approve ban/unban/remove <deviceId>",
        permission: "admin"
    },
    execute: async function (bot, msg, args) {
        try {
            if (!args.length) {
                return bot.sendMessage(msg.chat.id, "❌ Please specify a device ID or a command (ban/unban/remove)");
            }

            // Check for ban/unban command
            if (args[0].toLowerCase() === 'ban' && args[1]) {
                const deviceId = args[1];
                const BANNED_DEVICES_FILE = path.join(__dirname, '../../banned_devices.json');
                
                // Load current banned devices
                let bannedDevices = [];
                if (fs.existsSync(BANNED_DEVICES_FILE)) {
                    const data = fs.readFileSync(BANNED_DEVICES_FILE, 'utf8');
                    if (data) {
                        bannedDevices = JSON.parse(data);
                    }
                }
                
                // Check if device is already banned
                if (bannedDevices.includes(deviceId)) {
                    return bot.sendMessage(msg.chat.id, `❌ Device ${deviceId} is already banned.`);
                }
                
                // Add to banned devices
                bannedDevices.push(deviceId);
                fs.writeFileSync(BANNED_DEVICES_FILE, JSON.stringify(bannedDevices), 'utf8');
                
                // Remove from approved devices if present
                const APPROVED_DEVICES_FILE = path.join(__dirname, '../../approved_devices.json');
                if (fs.existsSync(APPROVED_DEVICES_FILE)) {
                    let approvedDevices = JSON.parse(fs.readFileSync(APPROVED_DEVICES_FILE, 'utf8'));
                    const index = approvedDevices.indexOf(deviceId);
                    if (index !== -1) {
                        approvedDevices.splice(index, 1);
                        fs.writeFileSync(APPROVED_DEVICES_FILE, JSON.stringify(approvedDevices), 'utf8');
                    }
                }
                
                return bot.sendMessage(msg.chat.id, `✅ Device ${deviceId} has been banned successfully.`);
            }
            
            if (args[0].toLowerCase() === 'unban' && args[1]) {
                const deviceId = args[1];
                const BANNED_DEVICES_FILE = path.join(__dirname, '../../banned_devices.json');
                
                // Load current banned devices
                let bannedDevices = [];
                if (fs.existsSync(BANNED_DEVICES_FILE)) {
                    const data = fs.readFileSync(BANNED_DEVICES_FILE, 'utf8');
                    if (data) {
                        bannedDevices = JSON.parse(data);
                    }
                }
                
                // Check if device is not banned
                const index = bannedDevices.indexOf(deviceId);
                if (index === -1) {
                    return bot.sendMessage(msg.chat.id, `❌ Device ${deviceId} is not banned.`);
                }
                
                // Remove from banned devices
                bannedDevices.splice(index, 1);
                fs.writeFileSync(BANNED_DEVICES_FILE, JSON.stringify(bannedDevices), 'utf8');
                
                // Add to approved devices if not already present
                const APPROVED_DEVICES_FILE = path.join(__dirname, '../../approved_devices.json');
                let approvedDevices = [];
                if (fs.existsSync(APPROVED_DEVICES_FILE)) {
                    const data = fs.readFileSync(APPROVED_DEVICES_FILE, 'utf8');
                    if (data) {
                        approvedDevices = JSON.parse(data);
                    }
                }
                
                if (!approvedDevices.includes(deviceId)) {
                    approvedDevices.push(deviceId);
                    fs.writeFileSync(APPROVED_DEVICES_FILE, JSON.stringify(approvedDevices), 'utf8');
                }
                
                return bot.sendMessage(msg.chat.id, `✅ Device ${deviceId} has been unbanned and approved.`);
            }
            
            // Check for remove command
            if (args[0].toLowerCase() === 'remove' && args[1]) {
                const deviceId = args[1];
                const APPROVED_DEVICES_FILE = path.join(__dirname, '../../approved_devices.json');
                
                // Load current approved devices
                let approvedDevices = [];
                if (fs.existsSync(APPROVED_DEVICES_FILE)) {
                    const data = fs.readFileSync(APPROVED_DEVICES_FILE, 'utf8');
                    if (data) {
                        approvedDevices = JSON.parse(data);
                    }
                }
                
                // Check if device is in the approved list
                const index = approvedDevices.indexOf(deviceId);
                if (index === -1) {
                    return bot.sendMessage(msg.chat.id, `❌ Device ${deviceId} is not in the approved list.`);
                }
                
                // Remove from approved devices
                approvedDevices.splice(index, 1);
                fs.writeFileSync(APPROVED_DEVICES_FILE, JSON.stringify(approvedDevices), 'utf8');
                
                return bot.sendMessage(msg.chat.id, `✅ Device ${deviceId} has been removed from the approved list.`);
            }
            
            // Handle the original approve functionality
            const deviceId = args[0];
            const APPROVED_DEVICES_FILE = path.join(__dirname, '../../approved_devices.json');
            
            // Load current approved devices
            let approvedDevices = [];
            if (fs.existsSync(APPROVED_DEVICES_FILE)) {
                const data = fs.readFileSync(APPROVED_DEVICES_FILE, 'utf8');
                if (data) {
                    approvedDevices = JSON.parse(data);
                }
            }
            
            // Check if device is already approved
            if (approvedDevices.includes(deviceId)) {
                return bot.sendMessage(msg.chat.id, `❌ Device ${deviceId} is already approved.`);
            }
            
            // Add to approved devices
            approvedDevices.push(deviceId);
            fs.writeFileSync(APPROVED_DEVICES_FILE, JSON.stringify(approvedDevices), 'utf8');
            
            return bot.sendMessage(msg.chat.id, `✅ Device ${deviceId} has been approved successfully.`);
            
        } catch (error) {
            console.error('Error in approve command:', error);
            return bot.sendMessage(msg.chat.id, "❌ An error occurred while processing your request.");
        }
    }
};
