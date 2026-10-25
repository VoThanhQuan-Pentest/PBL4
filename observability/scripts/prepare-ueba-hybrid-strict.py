#!/usr/bin/env python3
"""Prepare a fresh strict HYBRID generation declaration; no long job is started.

The existing frozen producer remains authoritative for the19.163m ordinary
normal/score-only source recipe. Matching normal FIT is shared only with each
fold's separately predeclared81500 labeled rows. This planning/prototype tool
does not select, fit, score, register, activate, or read holdout numeric files.
"""
import argparse
from dataclasses import asdict
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ueba-worker'))
from app.hybrid_strict_protocol import disk_plan, protocol_sha256, require_space, source_protocol
from app.policy import canonical

IMAGE = 'sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f'
PRODUCER = ROOT / 'observability/scripts/prepare-ueba-schema4.py'


def frozen_producer():
    spec = importlib.util.spec_from_file_location('strict_hybrid_frozen_source_producer', PRODUCER)
    producer = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = producer
    spec.loader.exec_module(producer)
    producer.source_binding()  # Includes exact immutable causal generator SHA.
    return producer


def bind_sources(producer):
    classpath, package = producer.workspace_identity(producer.DEFAULT_WORKSPACE, producer.DEFAULT_WORKSPACE_SHA256)
    generator = producer.load_generator()
    endpoint = producer.endpoint_identity(producer.DEFAULT_ENDPOINT_PROOF, producer.DEFAULT_ENDPOINT_SHA256,
        producer.DEFAULT_WORKSPACE_SHA256, package, generator)
    sources = producer.source_binding()
    extra = {str(path.relative_to(ROOT)): producer.digest(path) for path in (
        Path(__file__).resolve(), ROOT / 'ueba-worker/app/hybrid_strict_protocol.py')}
    return {'standard_producer': sources, 'new_protocol_sources': extra,
        'workspace_snapshot_sha256': producer.DEFAULT_WORKSPACE_SHA256, 'java': package,
        'endpoint_proof': endpoint, 'execution_image_id': IMAGE,
        'generator_blind_seeds': list(generator.BLIND_SEEDS)}, classpath, generator


def prepare(dataset_id, output=None, *, prototype=False):
    if os.environ.get('UEBA_DIAGNOSTIC_IMAGE_ID') != IMAGE or not Path('/.dockerenv').exists():
        raise ValueError('pinned Docker-only source preparation required')
    protocol = source_protocol(dataset_id)
    producer = frozen_producer()
    before, classpath, generator = bind_sources(producer)
    standard_recipe = [asdict(part) for part in producer.recipe('STRICT')]
    if sum(part['normal'] + part['positive'] for part in standard_recipe) != protocol['standard_numeric_rows']:
        raise ValueError('unchanged full standard STRICT population recipe required')
    parent = ROOT / 'observability/runtime' if output is None else Path(output).absolute().parent
    if any(path.is_symlink() for path in (parent, *parent.parents)) or not parent.is_dir():
        raise ValueError('canonical existing private output parent required')
    storage = disk_plan()
    free = shutil.disk_usage(parent).free
    require_space(free, storage, generation_only=True)
    if output is None:
        output = Path(tempfile.mkdtemp(prefix='hybrid-strict-protocol-', dir=parent))
    else:
        output = Path(output).absolute()
        if output.exists() or output.is_symlink(): raise ValueError('new protected declaration directory required')
        output.mkdir(mode=0o700)
    output.chmod(0o700)
    declaration = {'protocol': protocol, 'protocol_sha256': protocol_sha256(protocol),
        'source_identity': before, 'ordinary_strict_recipe': standard_recipe,
        'disk_preflight': {**storage, 'actual_free_bytes': free,
            'generation_only_preflight_passed': True, 'full_campaign_preflight_passed': free >= storage['required_free_bytes']},
        'new_frames_generated_before_declaration': 0, 'fit_or_score_calls': 0,
        'holdout_numeric_records_read': 0, 'old_numeric_data_read': False}
    producer.write_new(output / 'predeclared.private.json', declaration)
    probes = []
    if prototype:
        # Three actual Java-extracted training-only rows per fold; no holdout,
        # calibration or validation file or labels are opened by this probe.
        for fold in protocol['folds']:
            pending = output / f"probe-fold{fold['fold']}"
            pending.mkdir(mode=0o700)
            part = producer.Part(f"fold{fold['fold']}-labeled-training", 'READY', fold['fit_day'], 1, 1, 2)
            writer = producer.BatchShards(pending, part.split, 'probe000000')
            batch = [(0, [(0, None)]), (1, [(0, 0)]), (2, [(0, 4)])]
            state = producer.export_batch(generator, fold['labeled_training']['namespace'], part,
                batch, 0, classpath, output, writer, timeout=180)
            writer.flush()
            if state['evaluated_rows'] != 3: raise ValueError('actual training-only Java probe conservation required')
            if not writer.descriptors: raise ValueError('actual probe numeric shards must be persisted')
            probes.append({'fold': fold['fold'], 'actual_java_evaluated_rows': 3, 'statistics': state,
                           'shards': writer.descriptors, 'not_full_training_source': True})
    after, _, _ = bind_sources(producer)
    if before != after: raise ValueError('source/Java/protocol changed; no preparation receipt published')
    result = {'status': 'PROTOCOL_PREPARED_NOT_GENERATED', 'stage': 'STRICT_SOURCE', 'quality_gate': 'NOT_EVALUATED',
        'dataset_id': dataset_id, 'protocol_sha256': protocol_sha256(protocol),
        'predeclared_sha256': producer.digest(output / 'predeclared.private.json'),
        'source_identity_before': before, 'source_identity_after': after, 'source_identity_unchanged': True,
        'prototype_training_rows': sum(probe['actual_java_evaluated_rows'] for probe in probes), 'probes': probes,
        'fit_or_score_calls': 0, 'holdout_numeric_records_read': 0, 'long_generation_started': False,
        'full_source_complete': False, 'generation_only_preflight_passed': True,
        'full_campaign_preflight_passed': free >= storage['required_free_bytes'],
        'limitations': ['PROTOTYPE_IS_NOT_50000_OR81500_TRAINING_PROOF', 'NO_STRICT_SELECTION_OR_QUALITY_PROOF',
            'FULL_GENERATION_AND_NEW_PER_FOLD_LABEL_WRITER_REQUIRE_SEPARATE_START_AUTHORIZATION',
            'PILOT_COMPRESSION_RATIO_IS_NOT_VERIFIED_MILLION_CALIBRATION_UPPER_BOUND']}
    producer.write_new(output / 'result.private.json', result)
    return output, result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset-id', required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--prototype-java', action='store_true')
    args = parser.parse_args()
    try:
        output, result = prepare(args.dataset_id, args.output, prototype=args.prototype_java)
        print(canonical({'status': result['status'], 'output': str(output), 'quality_gate': result['quality_gate'],
            'prototype_training_rows': result['prototype_training_rows'], 'fit_or_score_calls': 0,
            'holdout_numeric_records_read': 0, 'long_generation_started': False}), flush=True)
    except Exception as error:
        raise SystemExit('Strict hybrid preparation refused: ' + type(error).__name__ + '; private artifacts retained') from None
