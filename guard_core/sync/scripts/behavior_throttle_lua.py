from guard_core.scripts.rule_hit_index_lua import ADD_TO_RULE_HIT_INDEX

BEHAVIOR_THROTTLE_SCRIPT = (
    ADD_TO_RULE_HIT_INDEX
    + """
local n = math.floor(#KEYS / 2)
local now = ARGV[1]
local member = ARGV[2]
local record_when_over = ARGV[3] == '1'
local counts = {}
local over = false
local index = KEYS[2 * n + 1]

for i = 1, n do
  local base = 5 + (i - 1) * 4
  redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', '(' .. ARGV[base + 2])
  counts[i] = redis.call('ZCARD', KEYS[i])
  if counts[i] >= tonumber(ARGV[base + 4]) then
    over = true
  end
end

if (not over) or record_when_over then
  for i = 1, n do
    local base = 5 + (i - 1) * 4
    if ARGV[base + 1] == '1' then
      local ttl = math.max(tonumber(ARGV[base + 3]), tonumber(ARGV[5]))
      redis.call('ZADD', KEYS[i], now, member)
      redis.call('EXPIRE', KEYS[i], ttl)
      add_to_rule_hit_index(index, KEYS[i], tonumber(ARGV[4]), ttl)
    end
  end
end

local trips = {}
for i = 1, n do
  local base = 5 + (i - 1) * 4
  local refuse_at = tonumber(ARGV[base + 4])
  if counts[i] >= refuse_at then
    local rank = counts[i] - refuse_at
    local entry = redis.call('ZRANGE', KEYS[i], rank, rank, 'WITHSCORES')
    local first = 0
    if redis.call('SET', KEYS[n + i], '1', 'NX', 'EX', ARGV[base + 3]) then
      first = 1
    else
      redis.call('EXPIRE', KEYS[n + i], ARGV[base + 3])
    end
    table.insert(trips, i)
    table.insert(trips, entry[2])
    table.insert(trips, first)
  end
end
return trips
"""
)
