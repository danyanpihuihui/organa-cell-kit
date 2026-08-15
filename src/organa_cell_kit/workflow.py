from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

COORDINATE_RE = re.compile(r"^[0-9]+\.bitmap$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class CellKitError(ValueError):
    pass


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _paths(project: Path):
    project = Path(project).resolve()
    return project, project / "cell-kit.json", project / ".cell-kit-state.json", project / "dist"


def _load(project: Path):
    project, config_path, state_path, dist = _paths(project)
    if not config_path.is_file() or not state_path.is_file():
        raise CellKitError("not an initialized Organa Cell Kit project")
    return project, _json(config_path), _json(state_path), dist


def _set_stage(project: Path, stage: str, **extra):
    _, _, state_path, _ = _paths(project)
    value = {"schema_version": "organa-cell-kit-state-v0.1", "stage": stage, "updated_at_utc": datetime.now(timezone.utc).isoformat(), **extra}
    _write(state_path, value)
    return value


def init(project: Path, *, coordinate: str, controller_address: str, base_url: str, cell_name: str, version: str = "0.1.0", verifier_base_url: str = "https://organa-proof-verifier.onrender.com"):
    project, config_path, state_path, dist = _paths(project)
    parsed = urlparse(base_url)
    if not COORDINATE_RE.fullmatch(coordinate) or not VERSION_RE.fullmatch(version):
        raise CellKitError("invalid coordinate or version")
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise CellKitError("base_url must be stable HTTPS without query or fragment")
    if not isinstance(controller_address, str) or len(controller_address) < 14 or any(ch.isspace() for ch in controller_address):
        raise CellKitError("invalid controller address")
    if project.exists() and any(project.iterdir()):
        raise CellKitError("project directory must be empty")
    project.mkdir(parents=True, exist_ok=True)
    config = {
        "schema_version": "organa-cell-kit-config-v0.1",
        "coordinate": coordinate,
        "cell_name": cell_name,
        "controller_address": controller_address,
        "controller_independence": "independent-controller-claimed-not-yet-verified",
        "base_url": base_url.rstrip("/"),
        "version": version,
        "verifier_base_url": verifier_base_url.rstrip("/"),
        "disclosure_policy": "public-metadata-and-proof-only",
    }
    _write(config_path, config)
    state = _set_stage(project, "initialized")
    (project / "README.md").write_text(f"# {cell_name}\n\nOrgana Cell Kit project for `{coordinate}`.\n", encoding="utf-8")
    return {**state, "config_path": str(config_path)}


def build(project: Path):
    project, config, state, dist = _load(project)
    if state["stage"] not in {"initialized", "built", "verified"}:
        raise CellKitError("build requires initialized state")
    if dist.exists():
        shutil.rmtree(dist)
    version = config["version"]
    base = f"{config['base_url']}/versions/{version}"
    version_dir = dist / "versions" / version
    version_dir.mkdir(parents=True)
    services = [{"id":"organa-proof-verifier","name":"Organa Proof Verifier","service_type":"artifact-verification","lifecycle_status":"pending","endpoint_status":"available","health_url":config['verifier_base_url']+'/health',"openapi_url":config['verifier_base_url']+'/openapi.json',"human_url":config['verifier_base_url']+'/',"disclosure_level":"L2_METADATA_PROOF"}]
    agents = [{"id":"organa-cell-orchestrator","name":"Organa Cell Orchestrator","role":"orchestrator","lifecycle_status":"pending","capabilities":["task-routing","proof-indexing","disclosure-enforcement"]}]
    registries = {
        "agent-registry.json":{"schema_version":"organa-registry-v0.1","coordinate":config['coordinate'],"registry_type":"agents","entries":agents},
        "service-registry.json":{"schema_version":"organa-registry-v0.1","coordinate":config['coordinate'],"registry_type":"services","entries":services},
        "proof-index.json":{"schema_version":"organa-registry-v0.1","coordinate":config['coordinate'],"registry_type":"proofs","entries":[{"id":"controller-claim","proof_type":"wallet-signature","lifecycle_status":"pending","signature_status":"pending-user-signature","request_url":base+'/signature-request.json'}]},
        "disclosure-policy.json":{"schema_version":"organa-disclosure-policy-v0.1","coordinate":config['coordinate'],"default_public_level":"L2_METADATA_PROOF","public_package_excludes":["credentials","private memory","raw strategy","candidate pools","account data"]},
    }
    hashes = {}
    for name, value in registries.items():
        _write(version_dir/name, value);hashes[name]=_sha((version_dir/name).read_bytes())
    resources=[{"path":name,"url":base+'/'+name,"sha256":digest} for name,digest in sorted(hashes.items())]
    manifest={"schema_version":"organa-cell-resolution-v0.1","coordinate":config['coordinate'],"cell_type":"organa-cell","title":config['cell_name'],"version":version,"created_at_utc":datetime.now(timezone.utc).isoformat(),"lifecycle_status":"pending","state_semantics":{"lifecycle_status":"declared object lifecycle","activation_status":"canonical publication activation","controller_signature_status":"controller authentication state","canonical_state_source":".well-known/organa.json"},"controller":{"address":config['controller_address'],"claim_type":"bitmap-controller-wallet-claim","signature_status":"pending-user-signature","signature_request_url":base+'/signature-request.json'},"public_base_url":base,"agents":agents,"services":services,"resources":resources,"disclosure_policy_url":base+'/disclosure-policy.json',"proof_index_url":base+'/proof-index.json'}
    _write(version_dir/'organa-cell.json',manifest)
    manifest_hash=_sha((version_dir/'organa-cell.json').read_bytes())
    message=f"Organa Cell Controller Claim v0.1\nDomain: organa-cell-controller-claim\nBitcoin network: mainnet\nCoordinate: {config['coordinate']}\nController address: {config['controller_address']}\nCell manifest: {base}/organa-cell.json\nCell manifest SHA-256: {manifest_hash}\nVersion: {version}\nSafety: This message does not transfer assets, authorize spending, create a transaction, PSBT, fee, or miner payment."
    request={"schema_version":"organa-controller-signature-request-v0.1","coordinate":config['coordinate'],"controller_address":config['controller_address'],"manifest_url":base+'/organa-cell.json',"manifest_sha256":manifest_hash,"signature_method":"BIP-322-simple-message-signature","message_encoding":"UTF-8","message":message,"message_sha256":_sha(message.encode()),"safety_notice":"Message signing only; no transaction, transfer, PSBT or fee."}
    _write(version_dir/'signature-request.json',request)
    discovery={"schema_version":"organa-well-known-v0.1","coordinate":config['coordinate'],"cell_type":"organa-cell","current_manifest":{"url":base+'/organa-cell.json',"sha256":manifest_hash,"version":version,"lifecycle_status":"pending"},"activation_status":"awaiting-controller-signature","controller_claim":{"status":"pending-user-signature","signature_request_url":base+'/signature-request.json','signature_request_sha256':_sha((version_dir/'signature-request.json').read_bytes()),"signature_method":"BIP-322-simple-message-signature"}}
    _write(dist/'.well-known/organa.json',discovery)
    state=_set_stage(project,"built",manifest_sha256=manifest_hash)
    return {**state,"dist":str(dist)}


def verify(project: Path):
    project, config, state, dist = _load(project)
    if state["stage"] not in {"built", "verified", "candidate-published", "signed", "active"}:
        raise CellKitError("verify requires built candidate")
    version_dir=dist/'versions'/config['version'];manifest=_json(version_dir/'organa-cell.json');errors=[]
    if manifest.get('coordinate')!=config['coordinate']:errors.append('coordinate mismatch')
    for item in manifest.get('resources',[]):
        path=version_dir/item['path']
        if not path.is_file() or _sha(path.read_bytes())!=item['sha256']:errors.append('resource mismatch: '+item['path'])
    request=_json(version_dir/'signature-request.json')
    if request.get('manifest_sha256')!=_sha((version_dir/'organa-cell.json').read_bytes()):errors.append('manifest hash mismatch')
    if request.get('message_sha256')!=_sha(request.get('message','').encode()):errors.append('message hash mismatch')
    if errors:return {"ok":False,"stage":state['stage'],"errors":errors}
    if state['stage'] in {'built','verified'}:state=_set_stage(project,'verified',manifest_sha256=request['manifest_sha256'])
    return {"ok":True,**state,"errors":[]}


def publish_candidate(project: Path):
    project, config, state, dist = _load(project)
    if state['stage']!='verified':raise CellKitError('publish-candidate requires verified stage')
    # Publication transport is intentionally external; this freezes a deterministic publish plan.
    plan={"schema_version":"organa-publish-plan-v0.1","stage":"candidate-published","base_url":config['base_url'],"publish_root":str(dist),"required_public_urls":[config['base_url']+'/.well-known/organa.json',f"{config['base_url']}/versions/{config['version']}/organa-cell.json",f"{config['base_url']}/versions/{config['version']}/signature-request.json"],"instruction":"Upload dist without changing bytes, then verify every URL before wallet signing."}
    _write(project/'publish-plan.json',plan)
    return _set_stage(project,'candidate-published',publish_plan=str(project/'publish-plan.json'))


def record_signature(project: Path, *, signature: str, signature_valid: bool):
    project, config, state, dist = _load(project)
    if state['stage']!='candidate-published':raise CellKitError('sign requires candidate-published stage')
    if not signature_valid:raise CellKitError('signature must be independently valid')
    version_dir=dist/'versions'/config['version'];request=_json(version_dir/'signature-request.json')
    claim={"schema_version":"organa-controller-claim-v0.1","coordinate":config['coordinate'],"controller_address":config['controller_address'],"claim_status":"signed","signature_method":request['signature_method'],"message_encoding":"UTF-8","manifest_url":request['manifest_url'],"manifest_sha256":request['manifest_sha256'],"message":request['message'],"message_sha256":request['message_sha256'],"signature":signature,"signature_valid":True}
    _write(version_dir/'controller-claim.json',claim)
    return _set_stage(project,'signed',controller_claim_sha256=_sha((version_dir/'controller-claim.json').read_bytes()))


def activate(project: Path):
    project, config, state, dist = _load(project)
    if state['stage']!='signed':raise CellKitError('activate requires valid signature')
    resolver=_json(dist/'.well-known/organa.json');version_dir=dist/'versions'/config['version'];claim_path=version_dir/'controller-claim.json'
    resolver['activation_status']='active';resolver['current_manifest']['lifecycle_status']='live';resolver['controller_claim'].update({'status':'signed','signed_claim_url':f"{config['base_url']}/versions/{config['version']}/controller-claim.json",'signed_claim_sha256':_sha(claim_path.read_bytes())})
    _write(dist/'.well-known/organa.json',resolver)
    return _set_stage(project,'active',canonical_resolver=str(dist/'.well-known/organa.json'))


def doctor(project: Path):
    project, config, state, dist = _load(project)
    checks = {
        "coordinate_format": bool(COORDINATE_RE.fullmatch(config.get("coordinate", ""))),
        "controller_address_present": isinstance(config.get("controller_address"), str) and len(config["controller_address"]) >= 14,
        "stable_https_base_url": urlparse(config.get("base_url", "")).scheme == "https",
        "distinct_controller_not_yet_verified": config.get("controller_independence") == "independent-controller-claimed-not-yet-verified",
        "public_only_disclosure": config.get("disclosure_policy") == "public-metadata-and-proof-only",
        "wallet_safety_acknowledgement_required": True,
    }
    blockers = [name for name, passed in checks.items() if not passed]
    next_action = {
        "initialized": "Run build, then verify.",
        "built": "Run verify and fix every reported error.",
        "verified": "Run publish-candidate and upload exact dist bytes.",
        "candidate-published": "Verify public URLs, personally sign the exact BIP-322 message, then independently verify it.",
        "signed": "Run activate and publish the updated Canonical Resolver.",
        "active": "Complete a public task and request independent-controller verification before network registration.",
    }.get(state["stage"], "Inspect project state.")
    return {"ok": not blockers, "stage": state["stage"], "checks": checks, "blockers": blockers, "next_action": next_action, "human_required": ["Confirm Bitmap control", "Publish from participant-owned account", "Personally approve final BIP-322 wallet signature"], "never_share": ["seed phrase", "private key", "wallet password", "transaction", "PSBT", "API key"]}


def status(project: Path):
    _, config, state, dist = _load(project)
    return {**state,"coordinate":config['coordinate'],"dist_exists":dist.is_dir()}
