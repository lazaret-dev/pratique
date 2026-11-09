"""Narrow borrowed-workspace checks, complementary to runtime and whole-crate IR.

This is not a general Rust parser or a promise to erase compiler-created copies.
It compares the used primitive graph with the committed clean-only API and checks
the caller's zero-only guard construction, borrow edges and cleanup coverage.
"""
import hashlib
import re

from preparation_lifecycle import _code, _item, _method, _normal


def _working_api(source):
    source = _code(source)
    declaration = re.search(r'\bpub\s+struct\s+BatchWorking128x64\s*\{', source)
    if not declaration:
        raise ValueError('Missing caller-owned batch workspace')
    adjacent_attributes = re.search(r'(?:#\[[^\]]*\]\s*)*$', source[:declaration.start()]).group()
    if re.search(r'\b(?:Clone|Copy)\b', adjacent_attributes):
        raise ValueError('Working state must not derive Clone/Copy')
    if re.search(r'\bimpl\s+(?:Clone|Copy)\s+for\s+BatchWorking128x64', source):
        raise ValueError('Working state must not implement Clone/Copy')
    _, fields = _item(source, r'\bpub\s+struct\s+BatchWorking128x64\s*\{')
    _, implementation = _item(source, r'\bimpl\s+BatchWorking128x64\s*\{')
    found = {'fields': _normal(fields)}
    for name in ['empty', 'output', 'words64_mut', 'words128_mut']:
        header, body = _method(implementation, name)
        found[name] = _normal(header + '{' + body + '}')
    if not found['empty'].startswith('fnempty()->Self{'):
        raise ValueError('Workspace constructor must accept no secret input')
    if not found['output'].startswith('fnoutput(&self)->&[u128;2]{'):
        raise ValueError('Workspace output must remain borrowed')
    for name in ['transpose_step', 'transpose_in_place',
                 'clmul64_batch_xor_prepared', 'clmul128_batch_xor_prepared']:
        header, body = _method(source, name)
        found[name] = _normal(header + '{' + body + '}')
    wide = found['clmul128_batch_xor_prepared']
    if not wide.startswith('fnclmul128_batch_xor_prepared(a:&[u128;64],b:&PreparedPolynomial128x64,working:&mutBatchWorking128x64,)'):
        raise ValueError('Wide batch graph must borrow raw input, key and workspace')
    narrow = found['clmul64_batch_xor_prepared']
    if not narrow.startswith('fnclmul64_batch_xor_prepared(a:&mut[u64;64],b:&Prepared64,product_planes:&mut[u64;128],result:&mutu128,)'):
        raise ValueError('Narrow batch graph must borrow coefficient/product/result storage')
    return found


def _caller_graph(caller):
    caller = _code(caller)
    _, implementation = _item(caller, r'\bimpl\s+Zeroize\s+for\s+BatchWorking128x64\s*\{')
    _, wipe = _method(implementation, 'zeroize')
    normal_wipe = _normal(wipe)
    for width in [64, 128]:
        expected = 'forwordsinself.words' + str(width) + '_mut(){words.zeroize();}'
        if expected not in normal_wipe:
            raise ValueError('Working-state volatile wipe coverage is incomplete')
    _, body = _method(caller, 'absorb_portable')
    normal = _normal(body)
    required = ['letmutblocks=Zeroizing::new([0u128;64]);',
                'letmutworking=Zeroizing::new(BatchWorking128x64::empty());',
                'clmul128_batch_xor_prepared(&blocks,prepared,&mutworking);',
                'acc=reduce(working.output()[0],working.output()[1]);']
    for item in required:
        if item not in normal:
            raise ValueError('Missing zero-only owner/borrow/output edge')
    if normal.index(required[1]) > normal.index(required[2]) or normal.index(required[2]) > normal.index(required[3]):
        raise ValueError('Output must follow computation in the retained owner')
    if re.search(r'\breturn\s+(?:working|blocks)\b|\b(?:working|blocks)\s*\.\s*clone\s*\(', body):
        raise ValueError('Populated batch ownership must not escape or clone')
    return {'wipe': normal_wipe, 'caller': normal}


def audit_working_source(production, caller, clean_source, circuit_source):
    found = _working_api(production)
    if found != _working_api(clean_source):
        raise ValueError('Production working API differs from committed clean-only code')
    if re.search(r'\bfn\s+transpose\s*\(', _code(production)):
        raise ValueError('Value-taking transpose must not remain in production')
    header, _ = _method(_code(circuit_source), 'planes_product')
    if '&mut[T;128]' not in _normal(header) or '->[T;128]' in _normal(header):
        raise ValueError('Circuit aggregate output must be borrowed')
    graph = _caller_graph(caller)
    for broken in [production.replace('a: &[u128; 64]', 'a: [u128; 64]'),
                   production.replace('pub fn output(&self) -> &[u128; 2]',
                                      'pub fn output(&self) -> [u128; 2]')]:
        if broken == production:
            raise ValueError('Working API negative control no longer matches')
        try:
            candidate = _working_api(broken)
            if candidate != _working_api(clean_source):
                continue
        except ValueError:
            continue
        raise ValueError('Borrowed-workspace negative control accepted')
    for broken in [caller.replace('self.words128_mut()', 'self.words64_mut()'),
                   caller.replace('clmul128_batch_xor_prepared(&blocks, prepared, &mut working)',
                                  'clmul128_batch_xor_prepared(blocks, prepared, &mut working)')]:
        if broken == caller:
            raise ValueError('Working caller negative control no longer matches')
        try:
            _caller_graph(broken)
        except ValueError:
            continue
        raise ValueError('Working cleanup/borrow negative control accepted')
    return {
        'graph': ['zero-only caller owners', 'borrowed raw blocks',
                  'retained coefficient/product/sum/output arrays',
                  'borrowed output reduction', 'lexical guard Drop',
                  'existing volatile Zeroize for every exposed slice'],
        'workspace_u64_words': 320,
        'workspace_u128_words': 5,
        'raw_block_u128_words': 64,
        'source_owned_aggregate_escapes_on_used_graph': 0,
        'clean_api_expression_match': True,
        'graph_sha256': hashlib.sha256(repr((sorted(found.items()), graph)).encode()).hexdigest(),
        'limits': 'Scope/volatile codegen requires whole-crate IR review; scalar nodes and compiler moves/registers/spills remain best effort',
    }
