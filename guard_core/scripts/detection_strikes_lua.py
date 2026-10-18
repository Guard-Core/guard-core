RECORD_DETECTION_STRIKES_SCRIPT = """
local function record(key, now, member, window_start, ttl, cap)
  redis.call('ZADD', key, now, member)
  redis.call('ZREMRANGEBYSCORE', key, '-inf', '(' .. window_start)
  redis.call('ZREMRANGEBYRANK', key, 0, -(cap + 1))
  redis.call('EXPIRE', key, ttl)
  return redis.call('ZCARD', key)
end
local now, base, window_start = ARGV[1], ARGV[2], ARGV[3]
local ttl, cap = ARGV[4], tonumber(ARGV[5])
local categories = #KEYS - 3
local counts = {}
for i = 1, categories do
  redis.call('SADD', KEYS[1], KEYS[i + 3])
  counts[i + 2] = record(KEYS[i + 3], now, base .. ':' .. i, window_start, ttl, cap)
end
redis.call('ZADD', KEYS[2], now, base .. ':total')
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', '(' .. window_start)
redis.call('ZREMRANGEBYRANK', KEYS[2], 0, -(cap + 1))
redis.call('EXPIRE', KEYS[2], ttl)
redis.call('EXPIRE', KEYS[1], ttl)
counts[1] = redis.call('ZCARD', KEYS[2])
counts[2] = redis.call('ZCOUNT', KEYS[3], window_start, '+inf')
return counts
"""

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
