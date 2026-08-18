from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pilot import PilotError, init_pilot, requester_publish, verifier_settle, verify_pilot_handoff, worker_run
from .pilot_identity import IdentityPilotError, prepare_identity, record_identity_signature
from .production_loop import ProductionLoopError, run_demo, verify_receipt, worker_execute_from_board
from .workflow import CellKitError, activate, build, doctor, init, publish_candidate, record_signature, status, verify


def _print(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def parser():
    p=argparse.ArgumentParser(prog='organa-cell-kit',description='Build and activate a verifiable Organa Bitmap Cell')
    sub=p.add_subparsers(dest='command',required=True)
    i=sub.add_parser('init');i.add_argument('project');i.add_argument('--coordinate',required=True);i.add_argument('--controller-address',required=True);i.add_argument('--base-url',required=True);i.add_argument('--cell-name',required=True);i.add_argument('--version',default='0.1.0');i.add_argument('--verifier-base-url',default='https://organa-proof-verifier.onrender.com')
    for name in ['build','verify','publish-candidate','activate','status','doctor']:
        x=sub.add_parser(name);x.add_argument('project')
    s=sub.add_parser('sign');s.add_argument('project');s.add_argument('--signature',required=True)
    d=sub.add_parser('run-demo',help='run the local same-controller multi-agent production simulation');d.add_argument('project');d.add_argument('--target-package');d.add_argument('--prepare-only',action='store_true')
    w=sub.add_parser('worker-run',help='discover an open board task and persist worker acceptance/result');w.add_argument('project');w.add_argument('--board',required=True);w.add_argument('--worker-id',required=True);w.add_argument('--verifier-id',required=True);w.add_argument('--verifier-coordinate',required=True);w.add_argument('--source-package',required=True)
    r=sub.add_parser('verify-receipt',help='verify an immutable production receipt');r.add_argument('project');r.add_argument('--receipt',required=True)
    pi=sub.add_parser('pilot-init',help='create a portable dq/n6 cross-controller pilot workspace');pi.add_argument('project');pi.add_argument('--fixture-source',required=True)
    pp=sub.add_parser('pilot-requester-publish',help='preflight and publish the requester public board package');pp.add_argument('project')
    pw=sub.add_parser('pilot-worker-run',help='import requester artifacts and export an n6 worker submission');pw.add_argument('project');pw.add_argument('--public-board',required=True)
    pv=sub.add_parser('pilot-verifier-settle',help='verify imported worker artifacts and settle local test credit only');pv.add_argument('project');pv.add_argument('--public-board',required=True);pv.add_argument('--worker-submission',required=True)
    ph=sub.add_parser('pilot-verify-handoff',help='fail-closed verification of a complete signed pilot handoff');ph.add_argument('project');ph.add_argument('--handoff',required=True)
    ip=sub.add_parser('pilot-identity-prepare',help='prepare requester/worker identity documents and human BIP-322 requests; verifier remains pending');ip.add_argument('project');ip.add_argument('--config',required=True)
    ir=sub.add_parser('pilot-identity-record-signature',help='record and independently verify one human BIP-322 signature');ir.add_argument('project');ir.add_argument('--role',required=True,choices=['requester','worker','verifier']);ir.add_argument('--signature',required=True)
    return p


def main(argv=None):
    args=parser().parse_args(argv);project=Path(args.project)
    try:
        if args.command=='init':result=init(project,coordinate=args.coordinate,controller_address=args.controller_address,base_url=args.base_url,cell_name=args.cell_name,version=args.version,verifier_base_url=args.verifier_base_url)
        elif args.command=='build':result=build(project)
        elif args.command=='verify':result=verify(project)
        elif args.command=='publish-candidate':result=publish_candidate(project)
        elif args.command=='sign':result=record_signature(project,signature=args.signature)
        elif args.command=='activate':result=activate(project)
        elif args.command=='doctor':result=doctor(project)
        elif args.command=='run-demo':result=run_demo(project,prepare_only=args.prepare_only,target_package=Path(args.target_package) if args.target_package else None)
        elif args.command=='worker-run':result=worker_execute_from_board(root=project,board_path=Path(args.board),worker_id=args.worker_id,verifier_id=args.verifier_id,verifier_coordinate=args.verifier_coordinate,source_package=Path(args.source_package))
        elif args.command=='verify-receipt':result=verify_receipt(Path(args.receipt),project_root=project)
        elif args.command=='pilot-init':result=init_pilot(project,fixture_source=Path(args.fixture_source))
        elif args.command=='pilot-requester-publish':result=requester_publish(project)
        elif args.command=='pilot-worker-run':result=worker_run(public_board_dir=Path(args.public_board),worker_workspace=project)
        elif args.command=='pilot-verifier-settle':result=verifier_settle(public_board_dir=Path(args.public_board),worker_submission_dir=Path(args.worker_submission),verifier_workspace=project)
        elif args.command=='pilot-verify-handoff':result=verify_pilot_handoff(Path(args.handoff),project_root=project)
        elif args.command=='pilot-identity-prepare':result=prepare_identity(project, json.loads(Path(args.config).read_text(encoding='utf-8-sig')))
        elif args.command=='pilot-identity-record-signature':result=record_identity_signature(project, args.role, args.signature)
        else:result=status(project)
        _print(result);return 0 if result.get('ok',True) else 2
    except (CellKitError, ProductionLoopError, PilotError, IdentityPilotError) as exc:
        _print({'ok':False,'error':str(exc)});return 2

if __name__=='__main__':raise SystemExit(main())
