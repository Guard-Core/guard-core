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
local categories = #KEYS - 2
local counts = {}
for i = 1, categories do
  redis.call('SADD', KEYS[1], KEYS[i + 2])
  counts[i + 1] = record(KEYS[i + 2], now, base .. ':' .. i, window_start, ttl, cap)
  redis.call('ZADD', KEYS[2], now, base .. ':total:' .. i)
end
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', '(' .. window_start)
redis.call('ZREMRANGEBYRANK', KEYS[2], 0, -(cap + 1))
redis.call('EXPIRE', KEYS[2], ttl)
redis.call('EXPIRE', KEYS[1], ttl)
counts[1] = redis.call('ZCARD', KEYS[2])
return counts
"""

FORGET_DETECTION_STRIKES_SCRIPT = """
for _, member in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  redis.call('DEL', member)
end
redis.call('DEL', KEYS[1], KEYS[2])
return 1
"""
