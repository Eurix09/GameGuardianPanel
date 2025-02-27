
local userFile = "/storage/emulated/0/Download/UserData.txt"
local baseUrl = "https://ggpanelzenoprivate.onrender.com"

local function isInternetAvailable()
    local response = gg.makeRequest(baseUrl .. "/execute/info", nil, nil, {timeout = 3000})
    return response and response.content ~= nil
end

if not isInternetAvailable() then
    gg.alert("❌ No Internet Connection! Please turn on Wi-Fi or mobile data.")
    return
end

local function saveCredentials(username, password)
    local file = io.open(userFile, "w+")
    if not file then
        return false, "Error: Could not save user credentials."
    end
    file:write(username .. "\n" .. password)
    file:close()
    return true
end

local function loadCredentials()
    local file = io.open(userFile, "r")
    if not file then return nil, nil end

    local username = file:read("*l")
    local password = file:read("*l")
    file:close()

    if not username or not password then
        os.remove(userFile)
        return nil, nil
    end

    return username, password
end

local function checkCredentials(username, password)
    if not username or not password or username == "" or password == "" then
        gg.alert("Invalid credentials!")
        return false
    end

    gg.sleep(100) 

    local url = string.format("%s/execute?username=%s&apiKey=%s", baseUrl, username, password)
    local response = gg.makeRequest(url)

    if not response or not response.content then
        gg.alert("Error: Connection failed. Check your internet.")
        return false
    end

    local data = response.content
    local error = data:match('"error"%s*:%s*"([^"]+)"')
    local message = data:match('"message"%s*:%s*"([^"]+)"')
    local deviceType = data:match('"type"%s*:%s*"([^"]+)"')
    local zipCode = data:match('"zipCode"%s*:%s*"([^"]+)"')
    local remainingDays = data:match('"Remaining Days"%s*:%s*(%d+)')
    local status = data:match('"status"%s*:%s*"([^"]+)"')

    if error then
        gg.alert("❌ Error: " .. error)
        os.remove(userFile)
        os.exit()
        return false
    end

    if status and remainingDays and tonumber(remainingDays) > 0 then
        local displayMessage = string.format(
            "✅ Status: %s\n📱 Device Type: %s\n📍 ZIP Code: %s\n⏳ Days Remaining: %s days",
            status,
            deviceType or "Unknown",
            zipCode or "Unknown",
            remainingDays
        )
        gg.alert(displayMessage)
        return true
    else
        gg.alert("❌ Key has expired!")
        os.remove(userFile)
        os.exit()
        return false
    end
end

local function getDeviceInfo()
    local response = gg.makeRequest(baseUrl .. "/execute/info")
    if not response or not response.content then
        return nil
    end
    return response.content:match('"zip"%s*:%s*"([^"]+)"')
end

local username, password = loadCredentials()

if not username or not password then
    local zipCode = getDeviceInfo()
    if not zipCode then
        gg.alert("The server panel is down. Please contact the owner on Telegram: @ZenoOnTop")
        return
    end

    local codeChoice = gg.choice({
        "📋 COPY MY CODE",
        "🔑 LOGIN",
        "❌ CANCEL"
    }, nil, "Your Code is: " .. zipCode)

    if not codeChoice then return end

    if codeChoice == 1 then
        gg.copyText(zipCode)
        gg.alert("Code Copied! Please send it to the owner.")
        return
    elseif codeChoice == 3 then
        return
    end

    local credentials = gg.prompt(
        {"Enter your username:", "Enter your password:"},
        {"", ""},
        {"text", "text"}
    )

    if not credentials then
        gg.alert("Login canceled.")
        return
    end

    username, password = credentials[1], credentials[2]
    local saved, err = saveCredentials(username, password)
    if not saved then
        gg.alert(err)
        return
    end
end

if checkCredentials(username, password) then
    gg.toast("✨ Welcome, VIP User!")
end
