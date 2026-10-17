ADD_TO_RULE_HIT_INDEX = """
local function add_to_rule_hit_index(index, key, max_members, ttl)
  if redis.call('SADD', index, key) == 1
      and redis.call('SCARD', index) > max_members then
    for _, member in ipairs(redis.call('SMEMBERS', index)) do
      if redis.call('EXISTS', member) == 0 then
        redis.call('SREM', index, member)
      end
    end
    if redis.call('SCARD', index) > max_members then
      redis.call('SREM', index, key)
    end
  end
  redis.call('EXPIRE', index, ttl)
end
"""

SUM_INDEXED_WINDOW_HITS_SCRIPT = """
local total = 0
for _, member in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  if redis.call('EXISTS', member) == 1 then
    total = total + redis.call('ZCOUNT', member, ARGV[1], '+inf')
  else
    redis.call('SREM', KEYS[1], member)
  end
end
return total
"""
