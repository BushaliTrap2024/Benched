from .parsers.claude_findings import parse_findings

def score(findings, known):
    found=parse_findings([f.model_dump() for f in findings] if not isinstance(findings,str) else findings)
    used=set(); tp=[]; fp=[]; matches=[]
    for index, finding in enumerate(found):
        match=next((v for v in known if v.id not in used and v.type==finding.type),None)
        if match:
            used.add(match.id); tp.append(match.model_dump()); matches.append({'finding_index':index,'reference_id':match.id})
        else: fp.append(finding.model_dump())
    fn=[v.model_dump() for v in known if v.id not in used]
    precision=len(tp)/len(found) if found else 0
    recall=len(tp)/len(known) if known else 1
    result=dict(TP=len(tp),FP=len(fp),FN=len(fn),precision=precision,recall=recall,
        f1=2*precision*recall/(precision+recall) if precision+recall else 0,
        agentFindings=[f.model_dump() for f in found],truePositives=tp,falsePositives=fp,falseNegatives=fn,matches=matches)
    for field,label in [('type','byType'),('severity','bySeverity')]:
        breakdown={}
        for key in dict.fromkeys([getattr(v,field) for v in known]+[v[field] for v in fp]):
            total=sum(getattr(v,field)==key for v in known); hits=sum(v[field]==key for v in tp); extra=sum(v[field]==key for v in fp)
            p=hits/(hits+extra) if hits+extra else 0; r=hits/total if total else 0
            breakdown[key]=dict(total=total,found=hits,precision=p,recall=r,f1=2*p*r/(p+r) if p+r else 0)
        result[label]=breakdown
    return result
