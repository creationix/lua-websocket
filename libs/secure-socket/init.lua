local openssl = require('openssl')
local loadResource
if module then
  function loadResource(path)
    return module:load(path)
  end
else
  loadResource = require('resource').load
end
local bit = require('bit')

local DEFAULT_CIPHERS = 'ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:' .. -- TLS 1.2
                        'RC4:HIGH:!MD5:!aNULL:!EDH'                     -- TLS 1.0

local DEFAULT_CA_STORE
do
  local data = assert(loadResource("./root_ca.dat"))
  DEFAULT_CA_STORE = openssl.x509.store:new()
  local index = 1
  local dataLength = #data
  while index < dataLength do
    local len = bit.bor(bit.lshift(data:byte(index), 8), data:byte(index + 1))
    index = index + 2
    local cert = assert(openssl.x509.read(data:sub(index, index + len)))
    index = index + len
    assert(DEFAULT_CA_STORE:add(cert))
  end
end

return function (socket, options)

  local ctx = openssl.ssl.ctx_new(
    options.protocol or 'TLSv1_2',
    options.ciphers or DEFAULT_CIPHERS)

  local key, cert, ca
  if options.key then
    key = assert(openssl.pkey.read(options.key, true, 'pem'))
  end
  if options.cert then
    cert = assert(openssl.x509.read(options.cert))
  end
  if options.ca then
    if type(options.ca) == "string" then
      ca = { assert(openssl.x509.read(options.ca)) }
    elseif type(options.ca) == "table" then
      ca = {}
      for i = 1, #options.ca do
        ca[i] = assert(openssl.x509.read(options.ca[i]))
      end
    else
      error("options.ca must be string or table of strings")
    end
  end
  if key and cert then
    assert(ctx:use(key, cert))
  end
  if ca then
    local store = openssl.x509.store:new()
    for i = 1, #ca do
      assert(store:add(ca[i]))
    end
    ctx:cert_store(store)
  elseif DEFAULT_CA_STORE then
    ctx:cert_store(DEFAULT_CA_STORE)
  else
    ctx:verify_mode(openssl.ssl.none)
  end

  ctx:options(bit.bor(
    openssl.ssl.no_sslv2,
    openssl.ssl.no_sslv3,
    openssl.ssl.no_compression))

  local ssocket = setmetatable({}, {
    __index = socket
  })
  local bin, bout = openssl.bio.mem(8192), openssl.bio.mem(8192)
  local ssl = ctx:ssl(bin, bout, options.server)


  local onPlain -- set by user
  local startup = coroutine.running() -- true till after handshake completes
  local handshake

  local function onHandshake(err, data)
    if err then
      return assert(coroutine.resume(startup, nil, err))
    end
    bin:write(data)
    if startup then
      return handshake()
    end

  end

  function handshake()
    if ssl:handshake() then
      local thread = startup
      startup = false
      socket:read_stop()
      return assert(coroutine.resume(thread))
    end
    if bout:pending() > 0 then
      local data = bout:read()
      socket:write(data, function(err)
        assert(not err, err)
        if startup then
          handshake()
        end
      end)
    end
  end

  socket:read_start(onHandshake)
  handshake()
  coroutine.yield()

  local function onCipher(err, data)
    if err then
      return onPlain(err)
    end
    bin:write(data)
    while true do
      local plainText, _ = ssl:read()
      if not plainText then
        -- if _ == 0 then
        --   Destroy socket?
        -- end
        break
      end
      onPlain(nil, plainText)
    end
  end

  function ssocket.read_start(_, callback)
    onPlain = callback
    return socket:read_start(onCipher)
  end

  function ssocket.write(_, plain, callback)
    ssl:write(plain)
    local chunks = {}
    while true do
      local cipher = bout:read()
      if #cipher == 0 then break end
      chunks[#chunks + 1] = cipher
    end
    return socket:write(chunks, callback)
  end

  return ssocket

end
