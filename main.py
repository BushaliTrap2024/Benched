import argparse,asyncio,json,sys
from pathlib import Path
from vulnbench.config import ROOT,load_task,load_config
from vulnbench.experiment import run
from vulnbench.references.generate import generate
from vulnbench.storage import read_records
from vulnbench.aggregation import aggregate
from vulnbench.repeatability import analyze

def main():
    parser=argparse.ArgumentParser(description='VulnBench JS 1.0 Python benchmark')
    parser.add_argument('--root',type=Path,default=ROOT)
    sub=parser.add_subparsers(dest='command',required=True)
    gen=sub.add_parser('generate-references'); gen.add_argument('--fixture',required=True); gen.add_argument('--overwrite',action='store_true'); gen.add_argument('--snyk',default='snyk'); gen.add_argument('--include-ignores',action='store_true')
    exp=sub.add_parser('run'); exp.add_argument('--task',action='append',required=True); exp.add_argument('--config',action='append',required=True); exp.add_argument('--repetitions',type=int,default=1); exp.add_argument('--output',type=Path); exp.add_argument('--dry-run',action='store_true')
    for name in ('aggregate','repeatability'):
        cmd=sub.add_parser(name); cmd.add_argument('results',type=Path)
    args=parser.parse_args(); root=args.root.resolve()
    try:
        if args.command=='generate-references': result=asyncio.run(generate(root,args.fixture,args.overwrite,args.snyk,include_ignores=args.include_ignores))
        elif args.command=='run':
            if args.dry_run:
                result={'tasks':[load_task(root,t)[0].model_dump() for t in args.task],'configurations':[load_config(root,c).model_dump() for c in args.config],'repetitions':args.repetitions}
            else:
                import uuid
                path=args.output or root/'results'/f'experiment-{uuid.uuid4().hex}.jsonl'
                records=asyncio.run(run(root,args.task,args.config,args.repetitions,path)); result={'output':str(path),'runs':len(records),'failed':sum(bool(r['failure']) for r in records)}
                print(json.dumps(result,indent=2)); return int(bool(result['failed']))
        else: result=(aggregate if args.command=='aggregate' else analyze)(read_records(args.results))
        print(json.dumps(result,indent=2)); return 0
    except (ValueError,OSError,RuntimeError) as error:
        print(str(error),file=sys.stderr); return 1
if __name__=='__main__': raise SystemExit(main())
