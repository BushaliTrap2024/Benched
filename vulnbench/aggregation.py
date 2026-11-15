from collections import defaultdict
from statistics import mean,stdev

def aggregate(records):
    groups=defaultdict(list)
    for record in records: groups[(record['task_id'],record['config_id'])].append(record)
    result=[]
    for (task,config),rows in groups.items():
        good=[r for r in rows if not r.get('failure') and r.get('score') is not None]
        scores=[r['score']['f1'] for r in good]
        result.append(dict(task_id=task,config_id=config,attempts=len(rows),successful=len(good),failures=len(rows)-len(good),
            f1=mean(scores) if scores else None,f1_stddev=stdev(scores) if len(scores)>1 else 0,
            precision=mean(r['score']['precision'] for r in good) if good else None,
            recall=mean(r['score']['recall'] for r in good) if good else None,
            duration_ms=mean(r['metrics']['sessionDurationMs'] for r in good) if good else None))
    return result
