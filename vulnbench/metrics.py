"""Observable tool statistics; token estimates are never SDK usage figures."""
def tool_stats(calls):
    result={}
    for call in calls:
        item=result.setdefault(call['tool'],dict(count=0,totalDurationMs=0,totalInputTokensEst=0,totalOutputTokensEst=0))
        item['count']+=1
        item['totalDurationMs']+=call['durationMs']
        item['totalInputTokensEst']+=call['inputTokensEst']
        item['totalOutputTokensEst']+=call['outputTokensEst']
    return result
