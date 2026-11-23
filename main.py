import argparse,asyncio,json,sys
from pathlib import Path
from vulnbench.config import ROOT,execution_sources,load_config
from vulnbench.experiment import run
from vulnbench.references.generate import generate
from vulnbench.storage import read_records
from vulnbench.aggregation import aggregate,aggregate_by_config
from vulnbench.repeatability import analyze
from vulnbench.robustness import compare

def main():
    parser=argparse.ArgumentParser(description='VulnBench JS 1.0 Python benchmark')
    parser.add_argument('--root',type=Path,default=ROOT)
    sub=parser.add_subparsers(dest='command',required=True)
    gen=sub.add_parser('generate-references'); gen.add_argument('--fixture',required=True); gen.add_argument('--overwrite',action='store_true',help='Explicitly install candidates as findings.json after preserving the original; default is candidates only'); gen.add_argument('--snyk',default='snyk'); gen.add_argument('--include-ignores',action='store_true')
    exp=sub.add_parser('run'); exp.add_argument('--task',action='append'); exp.add_argument('--config',action='append',required=True); exp.add_argument('--repetitions',type=int,default=1); exp.add_argument('--output',type=Path); exp.add_argument('--dry-run',action='store_true')
    selection=exp.add_mutually_exclusive_group()
    selection.add_argument('--variant')
    selection.add_argument('--all-variants',action='store_true')
    robustness=sub.add_parser('robustness')
    robustness.add_argument('results',type=Path,nargs='+')
    for name in ('aggregate','repeatability'):
        cmd=sub.add_parser(name); cmd.add_argument('results',type=Path)
        if name=='aggregate': cmd.add_argument('--level',choices=['task','config','all'],default='all')
        else: cmd.add_argument('--signature-path',choices=['basename','relative-path'],default='basename')
    args=parser.parse_args(); root=args.root.resolve()
    try:
        if args.command=='generate-references': result=asyncio.run(generate(root,args.fixture,args.overwrite,args.snyk,include_ignores=args.include_ignores))
        elif args.command=='run':
            if args.dry_run:
                if args.repetitions < 1:
                    raise ValueError('Repetitions must be positive')
                sources=list(execution_sources(root,args.task,args.variant,args.all_variants))
                result={'tasks':[task.model_dump() for task,_,_,_,_ in sources],'configurations':[load_config(root,c).model_dump() for c in args.config],'repetitions':args.repetitions}
                if args.variant is not None or args.all_variants:
                    result['sources']=[dict(task_id=task.id,fixture_id=task.fixture,variant_id=variant,source='transformed',project=str(project))
                                       for task,_,_,project,variant in sources]
            else:
                import uuid
                directory=root/'results'
                if args.variant is not None or args.all_variants:
                    directory=directory/'objective-b'
                path=args.output or directory/f'experiment-{uuid.uuid4().hex}.jsonl'
                selection_options = {}
                if args.variant is not None:
                    selection_options['variant'] = args.variant
                if args.all_variants:
                    selection_options['all_variants'] = True
                records=asyncio.run(run(root,args.task,args.config,args.repetitions,path,**selection_options))
                result={'output':str(path),'runs':len(records),'failed':sum(bool(r['failure'] or r.get('error')) for r in records)}
                print(json.dumps(result,indent=2)); return int(bool(result['failed']))
        elif args.command=='robustness':
            result=compare([record for path in args.results for record in read_records(path)])
        else:
            records=read_records(args.results)
            if args.command=='repeatability': result=analyze(records,path_mode=args.signature_path)
            elif args.level=='task': result=aggregate(records)
            elif args.level=='config': result=aggregate_by_config(records)
            else:
                originals=[record for record in records if record.get('variant_id') is None]
                result={'tasks':aggregate(records),'configurations':aggregate_by_config(originals)}
                if len(originals) != len(records):
                    result['transformed']=compare(records)['configurations']
        print(json.dumps(result,indent=2)); return 0
    except (ValueError,OSError,RuntimeError) as error:
        print(str(error),file=sys.stderr); return 1
if __name__=='__main__': raise SystemExit(main())
