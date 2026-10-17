SLIDING_WINDOW_HIT_SCRIPT = """
local count = 0
for i = 1, #KEYS do
  local base = 2 + (i - 1) * 2
  redis.call('ZADD', KEYS[i], ARGV[1], ARGV[2])
  redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', '(' .. ARGV[base + 1])
  if i == 1 then
    count = redis.call('ZCARD', KEYS[i])
  end
  redis.call('EXPIRE', KEYS[i], ARGV[base + 2])
end
return count
"""
