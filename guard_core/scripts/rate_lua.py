from guard_core.scripts.detection_strikes_lua import RECORD_STRIKES_LUA

RATE_LIMIT_SCRIPT = """
pcall(redis.replicate_commands)

local time = redis.call('TIME')
local now = tonumber(time[1]) + tonumber(time[2]) / 1000000
local tiers = #KEYS

for i = 1, tiers do
    local limit = tonumber(ARGV[2 * i - 1])
    local window = tonumber(ARGV[2 * i])

    redis.call('ZREMRANGEBYSCORE', KEYS[i], 0, now - window)

    local count = redis.call('ZCARD', KEYS[i])
    if count >= limit then
        local retry_after = window
        local oldest = redis.call('ZRANGE', KEYS[i], 0, 0, 'WITHSCORES')
        if oldest[2] then
            retry_after = math.max(1, math.ceil(tonumber(oldest[2]) + window - now))
        end
        return {i, count, retry_after}
    end
end

for i = 1, tiers do
    redis.call('ZADD', KEYS[i], now, now)
    redis.call('EXPIRE', KEYS[i], tonumber(ARGV[2 * i]) * 2)
end

return {0, 0, 0}
"""

BAN_FIRST_RATE_LIMIT_SCRIPT = """
pcall(redis.replicate_commands)

local meta = {}
for part in string.gmatch(ARGV[1] .. '|', '([^|]*)|') do
    meta[#meta + 1] = part
end
local bans, seen, clock = tonumber(meta[1]), meta[2], tonumber(meta[3])
local read = redis.call('MGET', unpack(KEYS, 1, bans + 1))
local version = read[bans + 1] or '0'
local clear = seen == '' or version == seen
local held = false
for i = 1, bans do
    local value = read[i]
    if value then
        held = true
        local expiry = tonumber(value)
        if expiry == nil or clock <= expiry then
            clear = false
        end
    end
end

local out = {}
if not clear then
    out[1] = 0
    for i = 1, bans + 1 do
        out[i + 1] = read[i]
    end
    return out
end

local time = redis.call('TIME')
local now = tonumber(time[1]) + tonumber(time[2]) / 1000000
local first = bans + 1
local tiers = #KEYS - first
local result = nil

for i = 1, tiers do
    local key = KEYS[first + i]
    local limit = tonumber(ARGV[2 * i])
    local window = tonumber(ARGV[2 * i + 1])

    redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

    local count = redis.call('ZCARD', key)
    if count >= limit then
        local retry_after = window
        local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
        if oldest[2] then
            retry_after = math.max(1, math.ceil(tonumber(oldest[2]) + window - now))
        end
        result = {i, count, retry_after}
        break
    end
end

if result == nil then
    for i = 1, tiers do
        redis.call('ZADD', KEYS[first + i], now, now)
        redis.call('EXPIRE', KEYS[first + i], tonumber(ARGV[2 * i + 1]) * 2)
    end
    result = {0, 0, 0}
end

if seen ~= '' and not held then
    out[1] = 1
else
    out[1] = 2
    for i = 1, bans + 1 do
        out[i + 1] = read[i]
    end
end
for _, value in ipairs(result) do
    out[#out + 1] = value
end
return out
"""

BAN_RATE_STRIKE_SCRIPT = (
    RECORD_STRIKES_LUA
    + """
pcall(redis.replicate_commands)

local meta = {}
for part in string.gmatch(ARGV[1] .. '|', '([^|]*)|') do
    meta[#meta + 1] = part
end
local bans, seen = tonumber(meta[1]), meta[2]
local clock, tiers = tonumber(meta[3]), tonumber(meta[4])
local read = redis.call('MGET', unpack(KEYS, 1, bans + 1))
local version = read[bans + 1] or '0'
local clear = seen == '' or version == seen
local held = false
for i = 1, bans do
    local value = read[i]
    if value then
        held = true
        local expiry = tonumber(value)
        if expiry == nil or clock <= expiry then
            clear = false
        end
    end
end

local out = {}
if not clear then
    out[1] = 0
    for i = 1, bans + 1 do
        out[i + 1] = read[i]
    end
    return out
end

local time = redis.call('TIME')
local now = tonumber(time[1]) + tonumber(time[2]) / 1000000
local first = bans + 1
local result = nil

for i = 1, tiers do
    local key = KEYS[first + i]
    local limit = tonumber(ARGV[2 * i])
    local window = tonumber(ARGV[2 * i + 1])

    redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

    local count = redis.call('ZCARD', key)
    if count >= limit then
        local retry_after = window
        local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
        if oldest[2] then
            retry_after = math.max(1, math.ceil(tonumber(oldest[2]) + window - now))
        end
        result = {i, count, retry_after}
        break
    end
end

local counts = {}
if result == nil then
    for i = 1, tiers do
        redis.call('ZADD', KEYS[first + i], now, now)
        redis.call('EXPIRE', KEYS[first + i], tonumber(ARGV[2 * i + 1]) * 2)
    end
    result = {0, 0, 0}
    counts = record_strikes(
        first + tiers + 1, meta[5], meta[6], meta[7], meta[8], tonumber(meta[9])
    )
end

if seen ~= '' and not held then
    out[1] = 1
else
    out[1] = 2
    for i = 1, bans + 1 do
        out[i + 1] = read[i]
    end
end
for _, value in ipairs(result) do
    out[#out + 1] = value
end
for _, value in ipairs(counts) do
    out[#out + 1] = value
end
return out
"""
)
