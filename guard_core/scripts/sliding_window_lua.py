from guard_core.scripts.rule_hit_index_lua import ADD_TO_RULE_HIT_INDEX

SLIDING_WINDOW_HIT_SCRIPT = (
    ADD_TO_RULE_HIT_INDEX
    + """
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', '(' .. ARGV[3])
local count = redis.call('ZCARD', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[4])
if KEYS[2] then
  add_to_rule_hit_index(KEYS[2], KEYS[1], tonumber(ARGV[5]), ARGV[4])
end
return count
"""
)
