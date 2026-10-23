RECORD_STRIKES_LUA = """
local function record(key, now, member, window_start, ttl, cap)
  redis.call('ZADD', key, now, member)
  redis.call('ZREMRANGEBYSCORE', key, '-inf', '(' .. window_start)
  redis.call('ZREMRANGEBYRANK', key, 0, -(cap + 1))
  redis.call('EXPIRE', key, ttl)
  return redis.call('ZCARD', key)
end
local function record_strikes(first, now, base, window_start, ttl, cap)
  local index, total, violations = KEYS[first], KEYS[first + 1], KEYS[first + 2]
  local categories = #KEYS - first - 2
  local counts = {}
  for i = 1, categories do
    local category_key = KEYS[first + 2 + i]
    redis.call('SADD', index, category_key)
    counts[i + 2] = record(category_key, now, base .. ':' .. i, window_start, ttl, cap)
  end
  redis.call('ZADD', total, now, base .. ':total')
  redis.call('ZREMRANGEBYSCORE', total, '-inf', '(' .. window_start)
  redis.call('ZREMRANGEBYRANK', total, 0, -(cap + 1))
  redis.call('EXPIRE', total, ttl)
  redis.call('EXPIRE', index, ttl)
  counts[1] = redis.call('ZCARD', total)
  counts[2] = redis.call('ZCOUNT', violations, window_start, '+inf')
  return counts
end
"""

RECORD_DETECTION_STRIKES_SCRIPT = (
    RECORD_STRIKES_LUA
    + """
return record_strikes(1, ARGV[1], ARGV[2], ARGV[3], ARGV[4], tonumber(ARGV[5]))
"""
)

BAN_CHECK_AND_RECORD_STRIKE_SCRIPT = (
    RECORD_STRIKES_LUA
    + """
local bans = tonumber(ARGV[6])
local seen, now = ARGV[7], tonumber(ARGV[8])
local values = redis.call('MGET', unpack(KEYS, 1, bans + 1))
local version = values[bans + 1] or '0'
local clear = seen == '' or version == seen
for i = 1, bans do
  local value = values[i]
  if value then
    local expiry = tonumber(value)
    if expiry == nil or now <= expiry then
      clear = false
    end
  end
end
if not clear then
  return {values, 0, {}}
end
return {
  values,
  1,
  record_strikes(bans + 2, ARGV[1], ARGV[2], ARGV[3], ARGV[4], tonumber(ARGV[5])),
}
"""
)

READ_DETECTION_CATEGORIES_SCRIPT = """
local found = {}
for _, member in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  if redis.call('ZCOUNT', member, ARGV[1], '+inf') > 0 then
    table.insert(found, member)
  else
    redis.call('SREM', KEYS[1], member)
  end
end
if redis.call('ZCOUNT', KEYS[2], ARGV[1], '+inf') > 0 then
  table.insert(found, 'rate_limit')
end
return found
"""

FORGET_DETECTION_STRIKES_SCRIPT = """
for _, member in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  redis.call('DEL', member)
end
redis.call('DEL', KEYS[1], KEYS[2])
return 1
"""

DETECTION_CATEGORIES_ACTIVE_LUA = """
local function detection_categories_active(index, violations, window_start)
  for _, member in ipairs(redis.call('SMEMBERS', index)) do
    if redis.call('ZCOUNT', member, window_start, '+inf') > 0 then
      return true
    end
  end
  return redis.call('ZCOUNT', violations, window_start, '+inf') > 0
end
"""
