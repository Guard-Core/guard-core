BEHAVIOR_THROTTLE_SCRIPT = """
local n = math.floor(#KEYS / 2)
local now = ARGV[1]
local member = ARGV[2]
local record_when_over = ARGV[3] == '1'
local counts = {}
local over = false
local recent = KEYS[2 * n + 1]

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
      redis.call('ZADD', KEYS[i], now, member)
      redis.call('EXPIRE', KEYS[i], ARGV[base + 3])
      redis.call('ZADD', recent, now, member .. ':' .. i)
    end
  end
  if recent then
    redis.call('ZREMRANGEBYSCORE', recent, '-inf', '(' .. ARGV[4])
    redis.call('EXPIRE', recent, ARGV[5])
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
