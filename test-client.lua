local connect = require('coro-net').connect
local codec = require('http-codec')
local p = require('pretty-print').prettyPrint

coroutine.wrap(function ()
  local read, write, socket = assert(connect {
    host = "luvit.io",
    port = 443,
    tls = {},
    encode = codec.encoder(),
    decode = codec.decoder()
  })
  write {
    method = "GET",
    path = "/",
    {"Host", "luvit.io"}
  }

  for chunk in read do
    if #chunk == 0 then break end
    p(chunk)
  end
  write()
end)()
