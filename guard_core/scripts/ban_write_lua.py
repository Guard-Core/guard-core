EXTEND_ONLY_BAN_WRITE_SCRIPT = """
local live = redis.call('GET', KEYS[1])
local live_expiry = live and tonumber(live)
if live_expiry and live_expiry >= tonumber(ARGV[1]) then
  return {0, live}
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
if ARGV[3] == '1' then
  redis.call('INCR', KEYS[2])
end
return {1, ARGV[1]}
"""
