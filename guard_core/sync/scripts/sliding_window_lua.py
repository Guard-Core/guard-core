from guard_core.scripts.rule_hit_index_lua import ADD_TO_RULE_HIT_INDEX

_RECORD_HIT = """
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', '(' .. ARGV[3])
local count = redis.call('ZCARD', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[4])
local refused = 0
if KEYS[2] then
  refused = add_to_rule_hit_index(KEYS[2], KEYS[1], tonumber(ARGV[5]), ARGV[4])
end
"""

SLIDING_WINDOW_HIT_SCRIPT = ADD_TO_RULE_HIT_INDEX + _RECORD_HIT + "return count\n"

# Same effect, replies {count, refused}: refused is 1 when the rule-hit index was
# full and the key was not indexed. Opt-in, so the reply of the script above stays
# the bare count for every other caller.
SLIDING_WINDOW_HIT_REFUSAL_SCRIPT = (
    ADD_TO_RULE_HIT_INDEX + _RECORD_HIT + "return {count, refused}\n"
)
