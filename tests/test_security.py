import json
from pathlib import Path

import pytest

from organa_cell_kit.workflow import CellKitError, build, doctor, init, publish_candidate, record_signature, verify

A="bc1qexamplecontrolleraddress0000000000000000000"
B="https://example.test/cell"


def prepared(tmp_path):
    init(tmp_path,coordinate="123.bitmap",controller_address=A,base_url=B,cell_name="Test")
    build(tmp_path);verify(tmp_path);publish_candidate(tmp_path)


def test_placeholder_and_empty_signature_are_rejected(tmp_path):
    prepared(tmp_path)
    for value in ["", "NOT_A_BIP322_SIGNATURE", "test-bip322-signature"]:
        with pytest.raises(CellKitError, match="BIP-322"):
            record_signature(tmp_path,signature=value)


def test_manifest_tamper_after_publish_is_rejected(tmp_path):
    prepared(tmp_path)
    manifest=tmp_path/'dist/versions/0.1.0/organa-cell.json'
    data=json.loads(manifest.read_text());data['title']='tampered';manifest.write_text(json.dumps(data))
    with pytest.raises(CellKitError, match="candidate changed"):
        record_signature(tmp_path,signature="anything")
    assert doctor(tmp_path)['ok'] is False


def test_message_self_hash_rewrite_is_not_canonical(tmp_path):
    init(tmp_path,coordinate="123.bitmap",controller_address=A,base_url=B,cell_name="Test");build(tmp_path)
    request=tmp_path/'dist/versions/0.1.0/signature-request.json';data=json.loads(request.read_text());data['message']='arbitrary';import hashlib;data['message_sha256']='sha256:'+hashlib.sha256(b'arbitrary').hexdigest();request.write_text(json.dumps(data))
    result=verify(tmp_path)
    assert result['ok'] is False
    assert any('canonically bound' in x for x in result['errors'])


def test_doctor_never_claims_independence_verified(tmp_path):
    init(tmp_path,coordinate="123.bitmap",controller_address=A,base_url=B,cell_name="Test")
    result=doctor(tmp_path)
    assert result['independent_adoption']['verified'] is False
    assert result['independent_adoption']['status']=='claimed-not-verified'
