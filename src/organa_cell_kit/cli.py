from __future__ import annotations

import argparse
import json
from pathlib import Path

from .workflow import CellKitError, activate, build, init, publish_candidate, record_signature, status, verify


def _print(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def parser():
    p=argparse.ArgumentParser(prog='organa-cell-kit',description='Build and activate a verifiable Organa Bitmap Cell')
    sub=p.add_subparsers(dest='command',required=True)
    i=sub.add_parser('init');i.add_argument('project');i.add_argument('--coordinate',required=True);i.add_argument('--controller-address',required=True);i.add_argument('--base-url',required=True);i.add_argument('--cell-name',required=True);i.add_argument('--version',default='0.1.0');i.add_argument('--verifier-base-url',default='https://organa-proof-verifier.onrender.com')
    for name in ['build','verify','publish-candidate','activate','status']:
        x=sub.add_parser(name);x.add_argument('project')
    s=sub.add_parser('sign');s.add_argument('project');s.add_argument('--signature',required=True);s.add_argument('--signature-valid',action='store_true',help='Assert an independent BIP-322 verifier has validated the exact message/address/signature tuple')
    return p


def main(argv=None):
    args=parser().parse_args(argv);project=Path(args.project)
    try:
        if args.command=='init':result=init(project,coordinate=args.coordinate,controller_address=args.controller_address,base_url=args.base_url,cell_name=args.cell_name,version=args.version,verifier_base_url=args.verifier_base_url)
        elif args.command=='build':result=build(project)
        elif args.command=='verify':result=verify(project)
        elif args.command=='publish-candidate':result=publish_candidate(project)
        elif args.command=='sign':result=record_signature(project,signature=args.signature,signature_valid=args.signature_valid)
        elif args.command=='activate':result=activate(project)
        else:result=status(project)
        _print(result);return 0 if result.get('ok',True) else 2
    except CellKitError as exc:
        _print({'ok':False,'error':str(exc)});return 2

if __name__=='__main__':raise SystemExit(main())
