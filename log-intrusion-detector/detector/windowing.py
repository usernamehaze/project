"""Generic sliding-time-window burst detection, shared by the SSH and web
rule sets so "has this key done X times in Y seconds" isn't implemented
twice.

Simplification (documented, not hidden): each key alerts at most once --
the first time its window count crosses the threshold. A source that goes
quiet and then bursts again later won't re-alert. That's a deliberate v1
scope cut, not an oversight -- see the README's limitations section.
"""

from collections import defaultdict, deque


def find_bursts(timestamped_items, key_fn, window_seconds, threshold, distinct_fn=None):
    """
    timestamped_items: iterable of (timestamp, item), MUST be sorted ascending by timestamp.
    key_fn(item) -> the grouping key (e.g. source IP).
    distinct_fn(item) -> if given, count DISTINCT values of this within the
        window instead of raw item count (e.g. distinct usernames tried).
    Returns: {key: {"first_alert_at": ts, "window_items": [item, ...]}}
    """
    windows = defaultdict(deque)
    alerted = {}

    for ts, item in timestamped_items:
        key = key_fn(item)
        if key in alerted:
            continue

        dq = windows[key]
        dq.append((ts, item))
        while dq and (ts - dq[0][0]).total_seconds() > window_seconds:
            dq.popleft()

        if distinct_fn:
            count = len({distinct_fn(i) for _, i in dq})
        else:
            count = len(dq)

        if count >= threshold:
            alerted[key] = {
                "first_alert_at": ts,
                "window_items": [i for _, i in dq],
            }

    return alerted
