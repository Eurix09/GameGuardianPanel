
const { readdirSync } = require("fs");

const eurix = {
    name: "help",
    description: "Shows the command list and descriptions"
};

async function execute(bot, msg, args) {
    const chatId = msg.chat.id;
    try {
        const commandsPath = process.cwd() + "/script/commands";
        const commandFiles = readdirSync(commandsPath).filter(file => file.endsWith(".js"));
        
        // Get all commands
        const commands = commandFiles.map(file => {
            const command = require(`${commandsPath}/${file}`);
            return command.eurix || {};
        });

        if (!args || args.length === 0) {
            // Show general help menu
            const commandList = commands.map(cmd => `/${cmd.name} - ${cmd.description || 'No description'}`).join('\n');
            
            const helpMessage = `📚 Available Commands:\n\n${commandList}\n\n` +
                              `Use /help <command> for detailed information.\n` +
                              `Need assistance? Contact @ZenoOnTop`;
            
            await bot.sendMessage(chatId, helpMessage);
            return;
        }

        // Show specific command help
        const commandName = args[0].toLowerCase();
        const command = commands.find(cmd => cmd.name && cmd.name.toLowerCase() === commandName);

        if (command) {
            const helpMessage = `Command: /${command.name}\n` +
                              `Description: ${command.description || 'No description available'}\n\n` +
                              `Need more help? Contact @ZenoOnTop`;
            
            await bot.sendMessage(chatId, helpMessage);
        } else {
            await bot.sendMessage(chatId, "❌ Command not found. Use /help to see all available commands.");
        }

    } catch (error) {
        console.error("Help command error:", error);
        await bot.sendMessage(chatId, "❌ An error occurred while fetching commands.");
    }
}

module.exports = {
    eurix,
    execute
};
