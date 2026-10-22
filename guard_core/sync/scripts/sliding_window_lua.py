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

# Same effect, but replies {count, 1} instead of the bare count when the rule-hit
# index was full and refused the key. Opt-in, so every other caller keeps the bare
# count, and a request whose key was indexed gets the same reply as before.
SLIDING_WINDOW_HIT_REFUSAL_SCRIPT = (
    ADD_TO_RULE_HIT_INDEX
    + _RECORD_HIT
    + "if refused == 1 then\n  return {count, 1}\nend\nreturn count\n"
)
