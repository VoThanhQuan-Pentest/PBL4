#!/usr/bin/env python3
"""Explicit foreground/resumable strict source generation; never model fitting.

Default invocation requires --allow-generation. --scoped-test exercises three
folds with2 normal+3 labeled supplement rows and can never become strict proof.
"""
import argparse
from collections import Counter
from dataclasses import asdict
from datetime import timedelta
import fcntl
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ueba-worker'))
from app.catalog import ShardedDataset, row_stats, utc
from app.hybrid_strict_dataset import FORMAT, load_hybrid_strict_fit, validate_standard_manifest
from app.hybrid_strict_protocol import disk_plan, protocol_sha256, require_space, source_protocol
from app.policy import canonical

SPEC = importlib.util.spec_from_file_location('strict_source_preparation_adapter', ROOT / 'observability/scripts/prepare-ueba-hybrid-strict.py')
prep = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = prep; SPEC.loader.exec_module(prep)


def source_identity(producer):
    identity, classpath, generator = prep.bind_sources(producer)
    identity['writer_sources'] = {str(path.relative_to(ROOT)): producer.digest(path) for path in (
        Path(__file__).resolve(), ROOT / 'ueba-worker/app/hybrid_strict_dataset.py')}
    return identity, classpath, generator


def blind_standard_final_view(producer):
    """Adapter-local publication audit: holdout bytes/hashes, never parsed rows."""
    original = producer.ShardedDataset
    class BlindGenerationView(original):
        def iter_shards(self, name):
            if name != 'holdout':
                yield from super().iter_shards(name)
                return
            for descriptor in self.split(name)['shards']:
                body = self._read(descriptor['path'], producer.MAX_SHARD_BYTES)
                if producer.hashlib.sha256(body).hexdigest() != descriptor['sha256']:
                    raise ValueError('unopened holdout numeric byte checksum changed')
            # Actual counts come from immutable committed producer receipts;
            # constructor validates their aggregate descriptor identities.
    producer.ShardedDataset = BlindGenerationView
    original_promote = producer.promote
    def promote_without_holdout_decode(output, committed, receipt):
        if receipt['split'] != 'holdout':
            return original_promote(output, committed, receipt)
        for descriptor in receipt['shards']:
            source = committed / (descriptor['id'] + '.json')
            body = producer.read_file(source, producer.MAX_SHARD_BYTES)
            if producer.hashlib.sha256(body).hexdigest() != descriptor['sha256']:
                raise ValueError('committed unopened holdout byte checksum mismatch')
            target = output / descriptor['path']
            if target.exists():
                if producer.digest(target) != descriptor['sha256']: raise ValueError('holdout projection changed')
            else: os.link(source, target)
    producer.promote = promote_without_holdout_decode
    return original


def actual_isolation(standard, fold, training, *, scoped_test=False):
    frames = {row['frame_id'] for row in training}
    hours = {(row['account_id'], utc(row['window_start']).strftime('%Y-%m-%dT%H')) for row in training}
    accounts = {row['account_id'] for row in training}
    if len(frames) != len(training) or len(hours) != len(training): raise ValueError('training identities are not unique')
    proof = {key: 0 for key in ('calibration_frame_overlap', 'calibration_account_hour_overlap',
        'validation_frame_overlap', 'validation_account_hour_overlap', 'unseen_validation_training_account_overlap')}
    latest = max(utc(row['window_start']) for row in training)
    if standard.manifest['stage'] in ('STRICT', 'PILOT'):
        calibration_latest = latest
        for name in (f'fold{fold}-calibration-ready', f'fold{fold}-calibration-cold', f'fold{fold}-validation'):
            role = 'validation' if name.endswith('validation') else 'calibration'
            for _, rows in standard.iter_shards(name):
                for row in rows:
                    at = utc(row['window_start'])
                    if at - latest <= timedelta(days=14): raise ValueError('actual training history gap violated')
                    if role == 'calibration': calibration_latest = max(calibration_latest, at)
                    elif at - calibration_latest <= timedelta(days=14): raise ValueError('actual calibration/validation gap violated')
                    proof[role + '_frame_overlap'] += row['frame_id'] in frames
                    proof[role + '_account_hour_overlap'] += (row['account_id'], at.strftime('%Y-%m-%dT%H')) in hours
                    if role == 'validation' and row['cohort'] == 'UNSEEN_READY':
                        proof['unseen_validation_training_account_overlap'] += row['account_id'] in accounts
        if any(proof.values()): raise ValueError('actual scored split/training identity overlap')
    proof['matching_fold_gaps_gt14days'] = True
    proof['actual_score_only_splits_scanned'] = True
    proof['numeric_holdout_opened'] = False
    return proof


def run(dataset_id, output, *, resume=False, scoped_test=False, maximum_batches=None, interrupt_after_export=False):
    if os.environ.get('UEBA_DIAGNOSTIC_IMAGE_ID') != prep.IMAGE or not Path('/.dockerenv').exists():
        raise ValueError('pinned Docker-only source generation required')
    producer = prep.frozen_producer(); protocol = source_protocol(dataset_id)
    identity, classpath, generator = source_identity(producer)
    output = producer.checked_path(output)
    if scoped_test:
        if shutil.disk_usage(output.parent).free < 1024 * 1024: raise ValueError('insufficient bounded fixture space')
    else:
        require_space(shutil.disk_usage(output.parent).free, disk_plan(), generation_only=True)
    if not resume: output.mkdir(mode=0o700)
    if output.stat().st_mode & 0o077: raise ValueError('private generation directory required')
    lock_fd = os.open(output / 'writer.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        declaration = {'protocol': protocol, 'protocol_sha256': protocol_sha256(protocol), 'source_identity': identity,
            'scope': 'SCOPED_TEST' if scoped_test else 'FULL_STRICT_SOURCE', 'fit_or_score_calls': 0,
            'new_frames_generated_before_declaration': 0, 'holdout_numeric_records_read': 0}
        declaration_path = output / 'predeclared.private.json'
        if resume:
            if producer.parse_json(producer.read_file(declaration_path, 2 * 1024 * 1024)) != declaration:
                raise ValueError('same-source predeclared resume required')
        else: producer.write_new(declaration_path, declaration)
        producer.replace_progress(output / 'state.private.json', {'stage': 'STANDARD_SOURCE_RUNNING', 'scope': declaration['scope']})
        standard_root = output / 'standard'
        if scoped_test:
            if not (standard_root / 'manifest.json').exists():
                standard_root.mkdir(mode=0o700, exist_ok=True); (standard_root / 'shards').mkdir(mode=0o700, exist_ok=True)
                splits = {}
                for fold in protocol['folds']:
                    parts = [producer.Part(f"fold{fold['fold']}-fit", 'READY', fold['fit_day'], 1, 2),
                        producer.Part(f"fold{fold['fold']}-calibration-ready", 'READY', fold['calibration']['start_day'], 1, 2),
                        producer.Part(f"fold{fold['fold']}-calibration-cold", 'COLD', fold['calibration']['start_day'], 1, 2),
                        producer.Part(f"fold{fold['fold']}-validation", 'UNSEEN_READY', fold['validation']['start_day'], 1, 2)]
                    for part in parts:
                        writer = producer.BatchShards(standard_root / 'shards', part.split, 'test000000')
                        producer.export_batch(generator, dataset_id, part, [(i, [(0, None)]) for i in range(2)], 0,
                            classpath, output, writer, 180); writer.flush()
                        splits[part.split] = producer.split_descriptor(writer.descriptors)
                manifest = {'catalog_schema_version': 2, 'dataset_id': dataset_id, 'stage': 'PILOT', 'data_provenance': 'DEMO_ONLY',
                    'feature_schema_version': 4, 'telemetry_contract_version': 3, 'feature_names': protocol['feature_names'], 'splits': splits}
                producer.write_new(standard_root / 'manifest.json', manifest)
        elif not (standard_root / 'manifest.json').exists():
            blind_standard_final_view(producer)
            result = producer.prepare(dataset_id, 'STRICT', output=standard_root, resume=standard_root.exists(), maximum_batches=maximum_batches)
            if result['status'] != 'COMPLETED': return result
        standard = ShardedDataset(standard_root)
        validate_standard_manifest(standard.manifest, dataset_id, scoped_test=scoped_test)
        if not scoped_test:
            generation = producer.parse_json(producer.read_file(standard_root / 'generation.identity.json', producer.MAX_RECEIPT_BYTES))
            if (standard.manifest.get('source_binding') != producer.source_binding()
                    or generation.get('source_binding') != producer.source_binding()
                    or generation.get('dataset_id') != dataset_id or generation.get('stage') != 'STRICT'
                    or standard.manifest.get('generation_identity_sha256') != producer.digest(standard_root / 'generation.identity.json')):
                raise ValueError('actual fresh standard source pre-generation identity mismatch')
        producer.replace_progress(output / 'state.private.json', {'stage': 'STANDARD_SOURCE_COMPLETE', 'standard_sha256': standard.sha256})
        completed = []
        for fold in protocol['folds']:
            number = fold['fold']; directory = output / f'labels-fold{number}'
            if (directory / 'manifest.private.json').exists():
                _, _, retained = load_hybrid_strict_fit(directory, producer.digest(directory / 'manifest.private.json'), allow_scoped_test=scoped_test)
                if retained['source_identity_before'] != identity or retained['standard_manifest_sha256'] != standard.sha256:
                    raise ValueError('completed fold no longer matches source/standard manifest')
                completed.append(number); continue
            directory.mkdir(mode=0o700, exist_ok=True)
            for name in ('normal', 'supplement', 'receipts', 'pending', 'abandoned'): (directory / name).mkdir(mode=0o700, exist_ok=True)
            for partial in (directory / 'pending').iterdir():
                if partial.is_symlink() or not partial.is_dir(): raise ValueError('invalid owned pending transaction')
                partial.rename(directory / 'abandoned' / (partial.name + '-' + str(time.time_ns())))
            decl = {'fold': number, 'scope': declaration['scope'], 'source_identity': identity,
                    'standard_manifest_sha256': standard.sha256, 'protocol_sha256': protocol_sha256(protocol), 'new_frames_generated_before_declaration': 0}
            decl_path = directory / 'predeclared.private.json'
            if decl_path.exists():
                if producer.parse_json(producer.read_file(decl_path, 2 * 1024 * 1024)) != decl: raise ValueError('fold declaration changed')
            else: producer.write_new(decl_path, decl)
            producer.replace_progress(output / 'state.private.json', {'stage': 'LABEL_FOLDS_RUNNING', 'fold': number})
            fit = standard.split(f'fold{number}-fit'); normal = []
            normal_descriptors = []
            for descriptor, rows in standard.iter_shards(f'fold{number}-fit'):
                normal.extend(rows); source = standard.root / descriptor['path']; target = directory / 'normal' / source.name
                if not target.exists(): os.link(source, target)
                if producer.digest(source) != descriptor['sha256'] or producer.digest(target) != descriptor['sha256']:
                    raise ValueError('shared normal source/target changed')
                normal_descriptors.append({**descriptor, 'path': 'normal/' + source.name})
            supplement_descriptors = []
            populations = (('READY', 1, 2),) if scoped_test else (('READY', 50, 7000), ('UNSEEN_READY', 14300, 2000), ('COLD', 7150, 1000))
            ordinal = 0
            existing = {path.name for path in (directory / 'receipts').iterdir()}
            if any(not name.startswith('label') or not name[5:].isdigit() for name in existing):
                raise ValueError('invalid committed transaction graph')
            if existing and existing != {f'label{index:06d}' for index in range(len(existing))}:
                raise ValueError('resume requires contiguous committed transaction prefix')
            for cohort, normal_count, positive_count in populations:
                part = producer.Part(f'fold{number}-labeled-training', cohort, fold['fit_day'], 1, normal_count, positive_count)
                # Labeled actors have exactly one evaluated window each.
                for start in range(0, normal_count + positive_count, 64):
                    batch = [(actor, [(0, None if actor < normal_count else ((4 if scoped_test and actor == 2 else actor - normal_count) % 5))])
                             for actor in range(start, min(start + 64, normal_count + positive_count))]
                    batch_id = f'label{ordinal:06d}'; committed = directory / 'receipts' / batch_id
                    receipt_path = committed / 'receipt.json'
                    assignment = producer.object_digest([asdict(part), batch])
                    if receipt_path.exists():
                        receipt = producer.parse_json(producer.read_file(receipt_path, 1024 * 1024))
                        if receipt['assignment_sha256'] != assignment or receipt['source_identity'] != identity: raise ValueError('resume receipt changed')
                    else:
                        pending = directory / 'pending' / batch_id; pending.mkdir(mode=0o700)
                        writer = producer.BatchShards(pending, part.split, batch_id)
                        state = producer.export_batch(generator, fold['labeled_training']['namespace'], part, batch, 0, classpath, output, writer, 1800)
                        writer.flush()
                        if interrupt_after_export: raise RuntimeError('owned SCOPED_TEST interruption before commit')
                        receipt = {'assignment_sha256': assignment, 'source_identity': identity, 'statistics': state,
                                   'shards': [{**item, 'path': 'supplement/' + Path(item['path']).name} for item in writer.descriptors]}
                        producer.write_new(pending / 'receipt.json', receipt)
                        pending.rename(committed)
                    for shard in receipt['shards']:
                        target = directory / shard['path']; source = committed / Path(shard['path']).name
                        if not target.exists(): os.link(source, target)
                        if producer.digest(directory / shard['path']) != shard['sha256']: raise ValueError('committed shard changed')
                    supplement_descriptors.extend(receipt['shards']); ordinal += 1
                    if source_identity(producer)[0] != identity: raise ValueError('source drift during labeled extraction')
            if existing - {f'label{index:06d}' for index in range(ordinal)}:
                raise ValueError('receipt outside declared label recipe')
            after, _, _ = source_identity(producer)
            if after != identity: raise ValueError('source drift before publication')
            supplement = [row for descriptor in supplement_descriptors for row in producer.parse_json(
                producer.read_file(directory / descriptor['path'], producer.MAX_SHARD_BYTES))]
            isolation = actual_isolation(standard, number, [*normal, *supplement], scoped_test=scoped_test)
            manifest = {'format': FORMAT, 'stage': 'STRICT_SOURCE', 'scope': declaration['scope'], 'quality_gate': 'NOT_EVALUATED',
                'fold': number, 'standard_manifest_sha256': standard.sha256, 'standard_fit': fit,
                'predeclared_sha256': producer.digest(decl_path), 'source_identity_before': identity, 'source_identity_after': after,
                'fit_or_score_calls': 0, 'holdout_numeric_records_read': 0,
                'isolation_proof': isolation,
                'sections': {'normal': {'shards': normal_descriptors}, 'supplement': {'shards': supplement_descriptors}}}
            path = directory / 'manifest.private.json'; producer.write_new(path, manifest)
            load_hybrid_strict_fit(directory, producer.digest(path), allow_scoped_test=scoped_test)
            completed.append(number)
        result = {'status': 'COMPLETE_UNQUALIFIED_SOURCE' if not scoped_test else 'COMPLETE_UNQUALIFIED_SCOPED_TEST',
            'stage': 'STRICT_SOURCE', 'quality_gate': 'NOT_EVALUATED', 'folds_completed': completed,
            'scope': declaration['scope'], 'fit_or_score_calls': 0, 'holdout_numeric_records_read': 0,
            'source_identity_before': identity, 'source_identity_after': source_identity(producer)[0]}
        result['producer_integrity_validation'] = 'OWN_GENERATED_ROWS_VALIDATED_DURING_WRITE_FINAL_HOLDOUT_BYTEHASH_ONLY'
        result['downstream_holdout_numeric_records_read'] = 0
        producer.replace_progress(output / 'state.private.json', result)
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset-id', required=True); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-generation', action='store_true', required=True)
    parser.add_argument('--resume', action='store_true'); parser.add_argument('--scoped-test', action='store_true')
    parser.add_argument('--maximum-standard-batches', type=int)
    args = parser.parse_args()
    try:
        result = run(args.dataset_id, args.output, resume=args.resume, scoped_test=args.scoped_test,
                     maximum_batches=args.maximum_standard_batches)
        print(canonical({key: result[key] for key in ('status', 'stage', 'scope', 'quality_gate', 'folds_completed',
            'fit_or_score_calls', 'downstream_holdout_numeric_records_read') if key in result}), flush=True)
    except Exception as error: raise SystemExit('Strict source writer refused: ' + type(error).__name__ + '; private partial artifacts retained') from None
