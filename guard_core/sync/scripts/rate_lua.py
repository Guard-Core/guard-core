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
