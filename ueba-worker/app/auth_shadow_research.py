"""Offline-only auth-context research; never publishes or installs a model.

Run selection and evaluation in separate supervised processes. The evaluation and
controls split files must not be made visible to the selection process.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import shutil
import time

import numpy as np
from .auth_shadow_contract import FEATURE_NAMES, RECIPES, SEEDS, validate
from .auth_shadow_model import export_classifier, fit_classifier, logits, score_components, validate_state
from .auth_shadow_serving import configured_shadow
from .normal_support import _signed_log
from .postlogin_contract import FEATURE_NAMES as BASE_NAMES
from .postlogin_serving import load_bytes

QUOTAS = {'train': 40000, 'calibration': 15000, 'development': 10000,
          'evaluation': 25000, 'controls': 10000}
CLASS_QUOTAS = {'train': (32000, 6000, 2000), 'calibration': (12000, 2400, 600),
                'development': (8000, 1500, 500), 'evaluation': (20000, 3000, 2000)}
CONTEXTS = np.asarray(['ROUTINE_CONTEXT', 'BEHAVIOR_REVIEW_CONTEXT', 'SERVICE_DEGRADATION_CONTEXT'])
CASES = ('case3', 'case4', 'case5')
NORMAL_RECIPES = ('browse', 'forgot_otp', 'mobile', 'two_devices', 'reset_return',
                  'high_traffic', 'transient_4xx', 'browser_update')
MAX_ARTIFACT = 4 * 1024**3
MIN_START_RAM = int(5.5 * 1024**3)
MIN_RUN_RAM = 3 * 1024**3
MIN_DISK = 9 * 1024**3


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write_new(path, value):
    # O_EXCL makes reservations and selection immutable even across interruptions.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(canonical(value))
        output.flush()
        os.fsync(output.fileno())


def load_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024**2:
        raise RuntimeError('unsafe or oversized research input: ' + str(path))
    return json.loads(path.read_bytes())


def available_ram():
    with open('/proc/meminfo', encoding='ascii') as stream:
        for line in stream:
            if line.startswith('MemAvailable:'):
                return int(line.split()[1]) * 1024
    raise RuntimeError('STOP_RESOURCE: MemAvailable unavailable')


class ResourceGuard:
    def __init__(self, data, out):
        self.data, self.out = data, out
        self.last = 0.0
        if available_ram() < MIN_START_RAM or shutil.disk_usage(out).free < MIN_DISK:
            raise RuntimeError('STOP_RESOURCE: insufficient starting RAM or disk')
        self.check(force=True)

    def check(self, force=False):
        if not force and time.monotonic() - self.last < 2:
            return
        self.last = time.monotonic()
        if available_ram() < MIN_RUN_RAM:
            raise RuntimeError('STOP_RESOURCE: host RAM below running limit')
        # The parent mounts data read-only and enforces CPU, memory and time limits.
        total = sum(p.stat().st_size for root in (self.data, self.out)
                    for p in root.rglob('*') if p.is_file() and not p.is_symlink())
        if total > MAX_ARTIFACT:
            raise RuntimeError('STOP_RESOURCE: artifact quota exceeded')


def admit(data, active_splits):
    manifest_path, protocol_path, parity_path = (data / name for name in
        ('manifest.json', 'protocol.json', 'producer-parity.json'))
    manifest, protocol, parity = map(load_json, (manifest_path, protocol_path, parity_path))
    if (manifest.get('format') != 'AUTH_CONTEXT_LAB_SOURCE_V1'
            or manifest.get('status') != 'SOURCE_CAPTURE_COMPLETE' or manifest.get('records') != 100000
            or manifest.get('data_provenance') != 'CONTROLLED_CLOCK_LAB'
            or manifest.get('feature_schema_version') != 7
            or manifest.get('protocol_sha256') != digest(protocol_path)):
        raise RuntimeError('sealed controlled source and protocol required')
    if (protocol.get('format') != 'AUTH_CONTEXT_RESEARCH_V2' or protocol.get('seed') != 20261027
            or protocol.get('schema') != 7 or protocol.get('features') != 81
            or protocol.get('expected_worker_image') != 'sha256:4a37528fba90444305c2bf7eb685e1fad6750cc146435c582ee024dcf82acd2b'
            or protocol.get('expected_producer_image') != 'sha256:02495bec4b4ec7024f86829b10464c7a283d1a2ecc398858b4eada2f2ae7e628'
            or protocol.get('recipes') != list(RECIPES) or protocol.get('seeds') != list(SEEDS)
            or protocol.get('normal_recipes') != list(NORMAL_RECIPES)
            or protocol.get('quotas') != {k: list(v) for k, v in CLASS_QUOTAS.items()}
                | {'controls': [5000, 5000, 0]}):
        raise RuntimeError('pre-registered research protocol differs')
    if (parity.get('status') != 'HARNESS_REEXPORT_PARITY_PASS'
            or parity.get('records') != 100000 or parity.get('feature_count') != 81
            or parity.get('manifest_sha256') != digest(manifest_path)
            or parity.get('protocol_sha256') != digest(protocol_path)):
        raise RuntimeError('complete source-bound producer parity required')
    if set(manifest.get('splits', {})) != set(QUOTAS):
        raise RuntimeError('exact split inventory required')
    groups = set()
    for split, count in QUOTAS.items():
        item = manifest['splits'][split]
        if (item.get('records') != count or item.get('file') != split + '.jsonl.gz'
                or item.get('raw_file') != split + '-raw.jsonl.gz'):
            raise RuntimeError('split quota/path differs')
        current = set(item.get('account_groups', []))
        if len(current) < 200 or groups.intersection(current):
            raise RuntimeError('split account groups overlap or too few')
        groups.update(current)
        if split in active_splits:
            path = data / item['file']
            if path.is_symlink() or digest(path) != item.get('sha256'):
                raise RuntimeError('split checksum differs: ' + split)
    return manifest, protocol, {'manifest_sha256': digest(manifest_path),
                                 'protocol_sha256': digest(protocol_path),
                                 'parity_sha256': digest(parity_path),
                                 'research_code_sha256': digest(Path(__file__)),
                                 'classifier_code_sha256': digest(Path(__file__).with_name('auth_shadow_model.py'))}


def rows_for(data, split, manifest):
    count = QUOTAS[split]
    values = np.empty((count, 81), dtype=np.float64)
    labels = np.empty(count, dtype=np.uint8)
    metadata, seen, seen_sessions = [], set(), set()
    allowed_accounts = set(manifest['splits'][split]['account_groups'])
    with gzip.open(data / (split + '.jsonl.gz'), 'rt', encoding='utf-8') as source:
        for i in range(count):
            line = source.readline(65537)
            if not line or len(line) >= 65537:
                raise RuntimeError('bounded complete split required')
            row = json.loads(line)
            identifier = row['episode_id']
            if identifier in seen or row['split'] != split or row['status'] != 'OBSERVED':
                raise RuntimeError('duplicate episode, split or coverage mismatch')
            seen.add(identifier)
            if row['account_group'] not in allowed_accounts or row['session_group'] in seen_sessions:
                raise RuntimeError('unregistered account or duplicate session')
            seen_sessions.add(row['session_group'])
            if type(row['context_label']) is not int or row['context_label'] not in (0, 1, 2):
                raise RuntimeError('independent context label required')
            if ((row['context_label'] == 0 and (row['family'] != 'routine' or row['recipe'] not in NORMAL_RECIPES))
                    or (row['context_label'] == 1 and row['family'] not in CASES)
                    or (row['context_label'] == 2 and row['family'] != 'operational')):
                raise RuntimeError('label and predeclared scenario differ')
            packet = row['snapshot']
            values[i] = validate(packet)
            if packet['snapshot_id'] != identifier:
                raise RuntimeError('snapshot identity mismatch')
            labels[i] = row['context_label']
            metadata.append({k: row[k] for k in ('episode_id', 'account_group', 'session_group', 'family', 'recipe')}
                            | {'as_of': packet['as_of'], 'trusted': packet['trusted_window_count']})
        if source.read(1):
            raise RuntimeError('extra split rows')
    if tuple(int((labels == n).sum()) for n in range(3)) != CLASS_QUOTAS[split]:
        raise RuntimeError('class quotas differ')
    for case in CASES:
        if not any(m['family'] == case and labels[i] == 1 for i, m in enumerate(metadata)):
            raise RuntimeError('missing review family')
    return values, labels, metadata


def candidate_scores(state, rows, baseline, guard):
    raw = np.empty(len(rows)); contexts = np.empty(len(rows), dtype=np.uint8)
    for start in range(0, len(rows), 32):
        guard.check()
        result = score_components(state, rows[start:start + 32], baseline)
        raw[start:start + 32], contexts[start:start + 32] = result['raw_score'], result['context_index']
    return raw, contexts


def comparator(state, threshold, rows, baseline, guard):
    raw, contexts = candidate_scores(state, rows, baseline, guard)
    return (contexts == 1) & (raw >= threshold), contexts


def baseline_scores(model, rows, metadata, guard):
    flags, contexts = [], []
    for start in range(0, len(rows), 32):
        guard.check()
        packets = [{'snapshot_id': m['episode_id'], 'evaluation_unit': 'SENSITIVE_ACTION_ATTEMPT',
                    'feature_schema_version': 6, 'feature_names': list(BASE_NAMES),
                    'features': rows[i, :65].tolist(), 'as_of': m['as_of'],
                    'baseline_established': True, 'trusted_window_count': m['trusted']}
                   for i, m in enumerate(metadata[start:start + 32], start)]
        for assessment in model.score(packets)['assessments']:
            flags.append(assessment['above_threshold'] and assessment['context'] == CONTEXTS[1])
            contexts.append(list(CONTEXTS).index(assessment['context']))
    return np.asarray(flags, dtype=bool), np.asarray(contexts, dtype=np.uint8)


def threshold_for(raw, contexts, labels, reference_flags):
    budget = int(reference_flags[labels == 0].sum())
    normal = np.sort(raw[(labels == 0) & (contexts == 1)])[::-1]
    return float(np.nextafter(normal[budget], np.inf)) if len(normal) > budget else float(raw.min())


def ci(success, total):
    if not total:
        return [0.0, 1.0]
    p = success / total; z = 1.959963984540054; d = 1 + z*z/total
    center = (p + z*z/(2*total))/d
    half = z*math.sqrt(p*(1-p)/total + z*z/(4*total*total))/d
    return [max(0.0, center-half), min(1.0, center+half)]


def metrics(flags, contexts, labels, metadata):
    families = np.asarray([m['family'] for m in metadata]); recipes = np.asarray([m['recipe'] for m in metadata])
    accounts = np.asarray([m['account_group'] for m in metadata]); normal = labels == 0
    review, ops = labels == 1, labels == 2
    recall = {case: float(flags[review & (families == case)].mean()) for case in CASES}
    per_legitimate = {name: int(flags[normal & (recipes == name)].sum()) for name in sorted(set(recipes[normal]))}
    confusion = [[int(np.sum((labels == actual) & (contexts == predicted))) for predicted in range(3)] for actual in range(3)]
    account_summary = {}
    for label, mask in [('normal', normal), ('review', review), ('operations', ops)]:
        ids = sorted(set(accounts[mask])); success = sum(bool(flags[mask & (accounts == ident)].any()) for ident in ids)
        account_summary[label] = {'groups': len(ids), 'groups_with_review': success, 'ci95': ci(success, len(ids))}
    return {'normal': int(normal.sum()), 'false_review': int(flags[normal].sum()),
            'behavior': int(review.sum()), 'true_review': int(flags[review].sum()),
            'operations': int(ops.sum()), 'recall_by_case': recall,
            'false_review_by_legitimate_control': per_legitimate,
            'operational_false_review': int(flags[ops].sum()),
            'operational_correct': int(np.sum(ops & (contexts == 2))),
            'confusion_matrix_context': confusion,
            'precision_review': float(flags[review].sum() / flags.sum()) if flags.any() else 0.0,
            'false_review_ci95_episode_naive': ci(int(flags[normal].sum()), int(normal.sum())),
            'recall_ci95_episode_naive': ci(int(flags[review].sum()), int(review.sum())),
            'episode_ci_method': 'WILSON_UNADJUSTED_FOR_ACCOUNT_CLUSTERING', 'accounts': account_summary}


def paired_account_bootstrap(candidate_flags, reference_flags, labels, metadata):
    """Paired resampling by account; descriptive lab evidence, not production qualification."""
    accounts = np.asarray([row['account_group'] for row in metadata])
    _, groups = np.unique(accounts, return_inverse=True)
    count = int(groups.max()) + 1 if len(groups) else 0
    if not count:
        raise ValueError('account groups required for paired comparison')
    normal, review = labels == 0, labels == 1
    def totals(values):
        return np.bincount(groups, weights=np.asarray(values, dtype=np.float64), minlength=count)
    normal_count, review_count = totals(normal), totals(review)
    fp_delta = totals(candidate_flags & normal) - totals(reference_flags & normal)
    tp_delta = totals(candidate_flags & review) - totals(reference_flags & review)
    choices = np.random.default_rng(20261027).integers(0, count, size=(2000, count))
    def interval(numerator, denominator):
        numer = numerator[choices].sum(axis=1); denom = denominator[choices].sum(axis=1)
        valid = denom > 0
        if valid.sum() != len(choices):
            raise ValueError('insufficient account groups for paired comparison')
        bounds = np.quantile(numer / denom, [0.025, 0.975])
        return [float(bounds[0]), float(bounds[1])]
    return {'method': 'PAIRED_ACCOUNT_CLUSTER_BOOTSTRAP', 'seed': 20261027,
            'resamples': 2000, 'groups': count,
            'false_review_rate_difference_ci95': interval(fp_delta, normal_count),
            'recall_difference_ci95': interval(tp_delta, review_count)}


def nonregression(candidate, reference, *, evaluation=False):
    by_group = all(n <= reference['false_review_by_legitimate_control'].get(k, 0)
                   for k, n in candidate['false_review_by_legitimate_control'].items())
    recall = all(candidate['recall_by_case'][k] >= reference['recall_by_case'][k] for k in CASES)
    floor = not evaluation or all(candidate['recall_by_case'][k] >= .9 for k in CASES)
    return (candidate['false_review'] <= reference['false_review'] and by_group and recall and floor
            and candidate['operational_false_review'] <= reference['operational_false_review']
            and candidate['operational_correct'] >= reference['operational_correct'])


def models():
    shadow = configured_shadow()
    shadow.baseline.verify_identity()
    if shadow.state['recipe']['name'] != 'A' or shadow.state['seed'] != 42:
        raise RuntimeError('pinned A-42 comparator required')
    return shadow, shadow.baseline


def model_identity(shadow):
    if (hashlib.sha256(load_bytes(shadow.directory, 'manifest.json', 32768)).hexdigest() != shadow.sha
            or hashlib.sha256(load_bytes(shadow.directory, 'model-state.json', 16 * 1024**2)).hexdigest()
               != shadow.manifest['state_sha256']):
        raise RuntimeError('pinned comparator files changed')
    return {'shadow_manifest_sha256': shadow.sha, 'baseline_manifest_sha256': shadow.baseline.manifest_sha256,
            'shadow_state_sha256': hashlib.sha256(canonical(shadow.state)).hexdigest(),
            'shadow_threshold': shadow.manifest['threshold']}


def check_output(data, out, shadow, *, fresh):
    if any(path.is_symlink() for path in (out, *out.parents)):
        raise RuntimeError('private output must not use symlinks')
    destination = out.resolve()
    for protected in (data.resolve(), shadow.directory.resolve(), shadow.baseline.directory.resolve()):
        if destination == protected or destination in protected.parents or protected in destination.parents:
            raise RuntimeError('research output overlaps data or model publication')
    if fresh and any(out.iterdir()):
        raise RuntimeError('selection output must be empty')


def select(data, out):
    if not out.is_dir():
        raise RuntimeError('precreated private output directory required')
    guard = ResourceGuard(data, out)
    manifest, _, binding = admit(data, ('train', 'calibration', 'development'))
    shadow, baseline = models()
    check_output(data, out, shadow, fresh=True)
    binding |= model_identity(shadow)
    write_new(out / 'selection-started.json', {'status': 'RESERVED', 'binding': binding})
    train, train_labels, _ = rows_for(data, 'train', manifest)
    cal, cal_labels, _ = rows_for(data, 'calibration', manifest)
    dev, dev_labels, dev_meta = rows_for(data, 'development', manifest)
    a_cal, _ = comparator(shadow.state, shadow.manifest['threshold'], cal, baseline, guard)
    a_dev, a_dev_context = comparator(shadow.state, shadow.manifest['threshold'], dev, baseline, guard)
    reference = metrics(a_dev, a_dev_context, dev_labels, dev_meta)
    trials = []
    for recipe in RECIPES:
        for seed in SEEDS:
            guard.check(force=True)
            trial = recipe['name'] + '-' + str(seed)
            write_new(out / (trial + '-fit-reserved.json'), {'id': trial, 'binding': binding, 'at': time.time()})
            model = fit_classifier(train, train_labels, recipe, seed)
            state = export_classifier(model, recipe, seed)
            # Test the exact trained artifact, without an additional fixture fit.
            np.testing.assert_allclose(logits(state, train[:32]), model._raw_predict(_signed_log(train[:32])), rtol=1e-12, atol=1e-12)
            del model
            state_path = out / (trial + '-state.json'); write_new(state_path, state)
            raw, contexts = candidate_scores(state, cal, baseline, guard)
            threshold = threshold_for(raw, contexts, cal_labels, a_cal)
            raw, contexts = candidate_scores(state, dev, baseline, guard)
            result = metrics((contexts == 1) & (raw >= threshold), contexts, dev_labels, dev_meta)
            entry = {'id': trial, 'recipe': recipe['name'], 'seed': seed, 'threshold': threshold,
                     'development': result, 'eligible': nonregression(result, reference),
                     'state_sha256': digest(state_path)}
            write_new(out / (trial + '-completed.json'), entry); trials.append(entry)
    eligible = [trial for trial in trials if trial['eligible']]
    baseline.verify_identity()
    if model_identity(shadow) != {key: binding[key] for key in model_identity(shadow)}:
        raise RuntimeError('comparator identity changed')
    if not eligible:
        write_new(out / 'selection.json', {'status': 'STOP_NO_IMPROVEMENT', 'binding': binding,
                                          'reference_development': reference, 'classifier_fits': 4,
                                          'normal_fits': 0, 'evaluation_opened': False})
        return
    chosen = min(eligible, key=lambda trial: (trial['development']['false_review'],
                 -trial['development']['true_review'] / trial['development']['behavior'], trial['recipe'], trial['seed']))
    write_new(out / 'selection.json', {'status': 'SELECTED', 'binding': binding, 'candidate': chosen,
                                      'reference_development': reference, 'classifier_fits': 4,
                                      'normal_fits': 0, 'evaluation_opened': False})


def check_controls(data):
    counts = Counter(); seen = set()
    with gzip.open(data / 'controls.jsonl.gz', 'rt', encoding='utf-8') as stream:
        for line in stream:
            if len(line) >= 65537:
                raise RuntimeError('control row too large')
            row = json.loads(line); ident = row['episode_id']
            if ident in seen or row['split'] != 'controls':
                raise RuntimeError('duplicate control or split mismatch')
            seen.add(ident)
            if row['family'] == 'cold':
                validate(row['snapshot'], require_ready=False)
                if row['status'] != 'OBSERVED' or row['snapshot']['baseline_established']:
                    raise RuntimeError('cold control marked ready')
            elif row['family'] != 'missing' or row['status'] != 'UNDETERMINED' or row['snapshot']:
                raise RuntimeError('missing coverage was filled')
            counts[row['family']] += 1
    if counts != {'cold': 5000, 'missing': 5000}:
        raise RuntimeError('control quotas differ')
    return dict(counts)


def evaluate(data, out):
    guard = ResourceGuard(data, out)
    selection_path = out / 'selection.json'; selection = load_json(selection_path)
    if selection.get('status') != 'SELECTED' or selection.get('evaluation_opened') is not False:
        raise RuntimeError('frozen successful selection required')
    manifest, _, binding = admit(data, ('evaluation', 'controls'))
    shadow, baseline = models(); binding |= model_identity(shadow)
    check_output(data, out, shadow, fresh=False)
    if binding != selection['binding']:
        raise RuntimeError('selection/source/model identity changed')
    selected = selection['candidate']; state_path = out / (selected['id'] + '-state.json')
    if digest(state_path) != selected['state_sha256']:
        raise RuntimeError('selected artifact changed')
    state = validate_state(load_json(state_path))
    # Reserve once before opening either held-out split, even if the process fails.
    write_new(out / 'evaluation-started.json', {'status': 'RESERVED', 'selection_sha256': digest(selection_path), 'binding': binding})
    values, labels, metadata = rows_for(data, 'evaluation', manifest)
    a_flags, a_context = comparator(shadow.state, shadow.manifest['threshold'], values, baseline, guard)
    a_result = metrics(a_flags, a_context, labels, metadata)
    flags, contexts = comparator(state, selected['threshold'], values, baseline, guard)
    result = metrics(flags, contexts, labels, metadata)
    b_flags, b_context = baseline_scores(baseline, values, metadata, guard)
    b_result = metrics(b_flags, b_context, labels, metadata)
    controls = check_controls(data)
    benefit = result['false_review'] < a_result['false_review'] or result['true_review'] > a_result['true_review']
    passed = nonregression(result, a_result, evaluation=True) and benefit
    paired = paired_account_bootstrap(flags, a_flags, labels, metadata)
    baseline.verify_identity()
    if model_identity(shadow) != {key: binding[key] for key in model_identity(shadow)}:
        raise RuntimeError('comparator identity changed')
    receipt = {'status': 'RESEARCH_PASS' if passed else 'STOP_NO_IMPROVEMENT', 'scope': 'OFFLINE_RESEARCH_ONLY',
               'data_provenance': 'CONTROLLED_CLOCK_LAB', 'binding': binding, 'selected_trial': selected['id'],
               'selected_state_sha256': selected['state_sha256'], 'threshold': selected['threshold'],
               'selection_sha256': digest(selection_path), 'classifier_fits': 4, 'normal_fits': 0,
               'a42': a_result, 'schema6_baseline': b_result, 'candidate': result,
               'candidate_minus_a42_account_bootstrap': paired,
               'controls_undetermined': controls, 'maximum_rss_bytes': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
               'automatic_enforcement': False, 'strict_production_qualified': False}
    write_new(out / 'research-receipt.json', receipt)


def benchmark(data, out):
    guard = ResourceGuard(data, out)
    selection_path, receipt_path = out / 'selection.json', out / 'research-receipt.json'
    selection, receipt = load_json(selection_path), load_json(receipt_path)
    if (selection.get('status') != 'SELECTED' or receipt.get('status') != 'RESEARCH_PASS'
            or receipt.get('selection_sha256') != digest(selection_path)):
        raise RuntimeError('successful frozen research receipt required')
    _, _, binding = admit(data, ('evaluation',))
    shadow, baseline = models(); binding |= model_identity(shadow)
    check_output(data, out, shadow, fresh=False)
    if binding != selection['binding'] or binding != receipt['binding']:
        raise RuntimeError('benchmark source/model identity changed')
    chosen = selection['candidate']; state_path = out / (chosen['id'] + '-state.json')
    if (digest(state_path) != chosen['state_sha256']
            or receipt.get('selected_state_sha256') != chosen['state_sha256']):
        raise RuntimeError('benchmark candidate changed')
    state = validate_state(load_json(state_path))
    write_new(out / 'benchmark-started.json', {'status': 'RESERVED',
              'research_receipt_sha256': digest(receipt_path), 'state_sha256': chosen['state_sha256']})
    sample = []
    with gzip.open(data / 'evaluation.jsonl.gz', 'rt', encoding='utf-8') as source:
        for _ in range(32):
            line = source.readline(65537)
            if not line or len(line) >= 65537:
                raise RuntimeError('bounded benchmark observations required')
            row = json.loads(line)
            if row['split'] != 'evaluation' or row['status'] != 'OBSERVED':
                raise RuntimeError('benchmark observations must be covered')
            sample.append(validate(row['snapshot']))
    measured = {}
    for batch_size in (1, 32):
        rows = np.asarray(sample[:batch_size], dtype=np.float64)
        for _ in range(100):
            guard.check(); score_components(state, rows, baseline)
        elapsed = []
        for _ in range(1000):
            guard.check(); started = time.perf_counter()
            score_components(state, rows, baseline)
            elapsed.append((time.perf_counter() - started) * 1000)
        measured[str(batch_size)] = {'warmup_batches': 100, 'measured_batches': 1000,
                                     'p95_ms': float(np.percentile(elapsed, 95))}
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    baseline.verify_identity()
    if model_identity(shadow) != {key: binding[key] for key in model_identity(shadow)}:
        raise RuntimeError('comparator identity changed')
    write_new(out / 'benchmark-receipt.json', {
        'status': 'BENCHMARK_PASS' if rss <= 448 * 1024**2 and measured['32']['p95_ms'] <= 100 else 'STOP_RESOURCE',
        'scope': 'OFFLINE_RESEARCH_ONLY', 'state_sha256': chosen['state_sha256'],
        'research_receipt_sha256': digest(receipt_path), 'batches': measured,
        'maximum_rss_bytes': rss, 'strict_production_qualified': False, 'automatic_enforcement': False})


def main():
    if os.environ.get('AUTH_RESEARCH_SUPERVISED') != '1':
        raise SystemExit('Use the resource-bounded auth_context_research_runner.py supervisor')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('select', 'evaluate', 'benchmark'))
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.stage == 'select':
        select(args.data, args.output)
    elif args.stage == 'evaluate':
        evaluate(args.data, args.output)
    else:
        benchmark(args.data, args.output)


if __name__ == '__main__':
    main()
