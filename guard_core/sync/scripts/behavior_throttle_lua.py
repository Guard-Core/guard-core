from guard_core.scripts.detection_strikes_lua import DETECTION_CATEGORIES_ACTIVE_LUA
from guard_core.scripts.rule_hit_index_lua import ADD_TO_RULE_HIT_INDEX

BEHAVIOR_THROTTLE_SCRIPT = (
    ADD_TO_RULE_HIT_INDEX
    + DETECTION_CATEGORIES_ACTIVE_LUA
    + """
local now = ARGV[1]
local member = ARGV[2]
local record_when_over = ARGV[3] == '1'
local n = tonumber(ARGV[6])
local counts = {}
local effective = {}
local over = false
local index = KEYS[2 * n + 1]
local index_refused = 0
local corr_known, corr_active = false, false
local corr_at_key = 2 * n + (ARGV[4] ~= '' and 1 or 0)

for i = 1, n do
  local base = 7 + (i - 1) * 5
  redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', '(' .. ARGV[base + 2])
  counts[i] = redis.call('ZCARD', KEYS[i])
  local refuse_at = tonumber(ARGV[base + 4])
  local correlated_at = tonumber(ARGV[base + 5])
  if correlated_at > 0 and counts[i] >= correlated_at and counts[i] < refuse_at then
    if not corr_known then
      corr_active = detection_categories_active(
        KEYS[corr_at_key + 1], KEYS[corr_at_key + 2], ARGV[7]
      )
      corr_known = true
    end
    if corr_active then
      refuse_at = correlated_at
    end
  end
  effective[i] = refuse_at
  if counts[i] >= refuse_at then
    over = true
  end
end

if (not over) or record_when_over then
  for i = 1, n do
    local base = 7 + (i - 1) * 5
    if ARGV[base + 1] == '1' then
      local ttl = math.max(tonumber(ARGV[base + 3]), tonumber(ARGV[5]))
      redis.call('ZADD', KEYS[i], now, member)
      redis.call('EXPIRE', KEYS[i], ttl)
      index_refused = index_refused + add_to_rule_hit_index(
        index, KEYS[i], tonumber(ARGV[4]), ttl
      )
    end
  end
end

local trips = {}
for i = 1, n do
  local base = 7 + (i - 1) * 5
  local refuse_at = effective[i]
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
    table.insert(trips, refuse_at)
  end
end
if index_refused > 0 then
  table.insert(trips, index_refused)
end
return trips
"""
)
