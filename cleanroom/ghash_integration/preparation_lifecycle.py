"""Narrow source-graph regression checks for retained key preparation.

These checks complement the borrow types, runtime storage tests and independent
source/IR review. They are not a general Rust parser or an erasure proof.
"""
import hashlib
import re


def _code(text):
    return re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)


def _item(text, pattern):
    match = re.search(pattern, text)
    if not match:
        raise ValueError('Missing preparation graph item: ' + pattern)
    opening = text.index('{', match.start())
    depth = 1
    end = opening + 1
    while depth and end < len(text):
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    if depth:
        raise ValueError('Unbalanced preparation item')
    return text[match.start():opening].strip(), text[opening + 1:end - 1]


def _method(implementation, name):
    return _item(implementation, r'\bfn\s+' + name + r'\b[^{}]*\{')


def _normal(text):
    return re.sub(r'\s+', '', text)


def _retained_api(source):
    source = _code(source)
    found = {}
    for typename, word in [('Prepared64', 'u64'), ('PreparedPolynomial128x64', 'u128')]:
        _, implementation = _item(source, r'\bimpl\s+' + typename + r'\s*\{')
        if re.search(r'\bfn\s+new\b', implementation):
            raise ValueError('Value-taking constructor is forbidden in retained preparation')
        empty_header, empty = _method(implementation, 'empty')
        if not re.fullmatch(r'fnempty\(\)->Self', _normal(empty_header)):
            raise ValueError('Empty must accept no secret input')
        header, body = _method(implementation, 'prepare')
        signature = _normal(header)
        match = re.fullmatch(r'fnprepare\(&mutself,([A-Za-z_]\w*):&\[' + word + r';64\]\)(?:->\(\))?', signature)
        if not match:
            raise ValueError('Preparation must borrow its raw input and return unit')
        argument = match.group(1)
        # This deliberately narrow retained API needs no local bindings. A new
        # local aggregate/copy must therefore be explicitly reviewed, not hidden
        # behind passing final-state tests.
        if re.search(r'\blet\b|\bSelf\s*[({]|\btranspose\s*\(|\.clone\s*\(|\.to_owned\s*\(', body):
            raise ValueError('Preparation introduced a scratch/copy/value route')
        if re.search(r'\*\s*' + argument + r'\b', body):
            raise ValueError('Preparation copies a whole borrowed input')
        calls = set(re.findall(r'\b([A-Za-z_]\w*)\s*\(', body))
        if calls - {'transpose_in_place', 'copy_from_slice'}:
            raise ValueError('Preparation introduced an unreviewed helper route')
        if 'transpose_in_place' not in calls:
            raise ValueError('Preparation must transpose retained storage in place')
        found[typename + '.empty'] = _normal(empty_header + '{' + empty + '}')
        found[typename + '.prepare'] = _normal(header + '{' + body + '}')
    for name in ['transpose_in_place', 'transpose_step']:
        header, body = _method(source, name)
        if '&mut[u64;64]' not in _normal(header):
            raise ValueError('Transpose graph must borrow retained storage')
        if re.search(r'\*\s*q\b|\blet\b[^;=]*=\s*\[', body):
            raise ValueError('Transpose graph introduced an array copy')
        found[name] = _normal(header + '{' + body + '}')
    return found


def audit_preparation_source(production, caller, clean_source, guarded_source=None,
                             clean_guarded_source=None, zeroize_source=None):
    found = _retained_api(production)
    if found != _retained_api(clean_source):
        raise ValueError('Production preparation differs from committed clean-only expressions')
    caller = _code(caller)
    if guarded_source is not None:
        from guarded_lifecycle import audit_guarded_preparation
        guarded = audit_guarded_preparation(
            guarded_source, caller, clean_guarded_source, zeroize_source)
    else:
        guarded = None
    header, body = _method(caller, 'prepare_powers')
    if guarded is None and ('&mutPreparedPolynomial128x64' not in _normal(header) or '->' in header):
        raise ValueError('Power helper must borrow its final retained destination')
    if 'PreparedPolynomial128x64::new' in body or 'transpose(' in _normal(body):
        raise ValueError('Power helper reintroduced the value-taking route')
    if not re.search(r'\.prepare\s*\(\s*&powers\s*\)', body):
        raise ValueError('Caller-owned raw powers must be borrowed')
    if re.search(r'\breturn\b', body):
        raise ValueError('Power helper must not exit before wiping its raw buffers')
    for value in ([] if guarded else ['powers', 'power']):
        if not re.search(r'\b' + value + r'\.zeroize\s*\(\s*\)', body):
            raise ValueError('Caller-owned raw powers/scalar wipe is missing')
        if body.index(value + '.zeroize') < body.index('.prepare'):
            raise ValueError('Raw buffer wipe must follow borrowed preparation')
    _, constructor_impl = _item(caller, r'\bimpl\s+GhashKey\s*\{')
    _, constructor = _method(constructor_impl, 'new')
    normalized = _normal(constructor)
    retained_type = 'PreparedPolynomial128x50' if guarded else 'PreparedPolynomial128x64'
    if 'Some(' + retained_type + '::empty())' not in normalized:
        raise ValueError('Retained field must start with zero state')
    if 'key.portable_powers.as_mut()' not in normalized:
        raise ValueError('Preparation must borrow the actual retained key field')
    if normalized.index('GhashKey{') > normalized.index('prepare_powers('):
        raise ValueError('Retained key must exist before preparation')
    # Negative controls test the structural rules independently of the clean
    # source equality check.
    for broken in [
        production.replace('b: &[u128; 64]', 'b: [u128; 64]'),
        production.replace('pub fn prepare(&mut self, b: &[u128; 64]) {',
                           'pub fn prepare(&mut self, b: &[u128; 64]) { let scratch = *b;'),
        production.replace('transpose_in_place(&mut self.low.0)', 'transpose(self.low.0)'),
    ]:
        if broken == production:
            raise ValueError('Preparation negative control no longer matches source')
        try:
            _retained_api(broken)
        except ValueError:
            continue
        raise ValueError('Unsafe preparation ownership negative control accepted')
    return {'preparation_graph': ['borrowed raw powers', 'retained planes',
                                 'in-place transpose', 'borrowed transpose steps'],
            'source_owned_preparation_scratch_arrays': 0,
            'caller_raw_powers_and_scalar_wipes': True,
            'guarded_50_lane_preparation': guarded,
            'clean_api_expression_match': True,
            'graph_sha256': hashlib.sha256(repr(sorted(found.items())).encode()).hexdigest(),
            'limitation': 'Object moves and compiler-created register/stack copies remain best effort'}
