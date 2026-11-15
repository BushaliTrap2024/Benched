from collections import defaultdict,Counter
import posixpath

def analyze(records):
    groups=defaultdict(list)
    for record in records:
        if not record.get('failure'): groups[(record['task_id'],record['config_id'])].append(record)
    output=[]
    for (task,config),rows in groups.items():
        matched=Counter(); unmatched=Counter()
        for row in rows:
            detail=row['score']
            matched.update({m['reference_id'] for m in detail['matches']})
            unmatched.update({(f['type'],posixpath.normpath(f['file'].replace('\\','/')),f.get('line')) for f in detail['falsePositives']})
        def summarize(counter):
            return dict(unique=len(counter),frequency_histogram=dict(sorted(Counter(counter.values()).items())),
                seen_once=sum(v==1 for v in counter.values()),seen_several=sum(1<v<len(rows) for v in counter.values()),
                seen_all=sum(v==len(rows) for v in counter.values()),
                signatures=[{'signature':key,'runs':value} for key,value in counter.items()])
        output.append(dict(task_id=task,config_id=config,successful_runs=len(rows),requested_repetitions=max(r['total_repetitions'] for r in rows),
            reference_matched=summarize(matched),unmatched=summarize(unmatched)))
    return output
