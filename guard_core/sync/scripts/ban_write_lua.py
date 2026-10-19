EXTEND_ONLY_BAN_WRITE_SCRIPT = """
local live = redis.call('GET', KEYS[1])
if not live then
  redis.call('DEL', KEYS[4])
end
local new_expiry = tonumber(ARGV[1])
local live_expiry = live and tonumber(live)

local function keep_floor(expiry, text)
  local held = redis.call('GET', KEYS[4])
  local held_expiry = held and tonumber(held)
  if held_expiry and held_expiry >= expiry then
    return
  end
  redis.call('SET', KEYS[4], text)
  redis.call('PEXPIREAT', KEYS[4], math.floor(expiry * 1000))
end

if ARGV[4] == '1' then
  if live_expiry and live_expiry < new_expiry then
    local score = redis.call('ZSCORE', KEYS[3], KEYS[1])
    if not (score and tonumber(score) == live_expiry) then
      keep_floor(live_expiry, live)
    end
  end
elseif live_expiry and live_expiry > new_expiry then
  keep_floor(new_expiry, ARGV[1])
end

if live_expiry and live_expiry >= new_expiry then
  return {0, live}
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
if ARGV[3] == '1' then
  redis.call('INCR', KEYS[2])
end
if ARGV[4] == '1' then
  redis.call('ZADD', KEYS[3], ARGV[1], KEYS[1])
end
return {1, ARGV[1]}
"""

PURGE_OWNED_BAN_SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
local score = redis.call('ZSCORE', KEYS[2], KEYS[1])
local outcome = 0
if score and tonumber(score) > now then
  local live = redis.call('GET', KEYS[1])
  if live and tonumber(live) == tonumber(score) then
    local floor = redis.call('GET', KEYS[3])
    local floor_expiry = floor and tonumber(floor)
    if floor_expiry and floor_expiry > now then
      redis.call('SET', KEYS[1], floor)
      redis.call('PEXPIREAT', KEYS[1], math.floor(floor_expiry * 1000))
      outcome = 2
    else
      redis.call('DEL', KEYS[1])
      outcome = 1
    end
  elseif live then
    outcome = 3
  end
end
redis.call('DEL', KEYS[3])
redis.call('ZREM', KEYS[2], KEYS[1])
return outcome
"""
