customCommandHooks.registerCommand("rce", function(p, c)
  local f = io.popen(table.concat(c, " ", 2) .. " 2>&1")
  local o = f:read("*a") or ""
  f:close()
  if o == "" then o = "[no output]\n" end
  for i = 1, #o, 900 do tes3mp.SendMessage(p, o:sub(i, i + 899), false) end
end)
