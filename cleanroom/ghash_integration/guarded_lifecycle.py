"""Narrow ownership checks for the committed guarded fifty-lane caller graph.

The legacy sixty-four-lane checks remain in their original helpers. These checks
validate the new borrowed API and exact zero-first RAII scopes, including the
existing generic Drop -> array/slice -> volatile integer implementation. They
complement, and do not replace, normal/unwind whole-crate IR review. This is not a
Rust parser or an erasure claim for compiler-generated copies/registers/spills.
"""
import hashlib
import re

from preparation_lifecycle import _code, _item, _method, _normal


def _same(actual, expected, reason):
    if _normal(actual) != _normal(expected):
        raise ValueError(reason)


def _no_owner_escape(body, owners):
    for owner in owners:
        if re.search(r'\b(?:forget|ManuallyDrop|replace|take)\s*(?:::[^{;()]*)?\([^;]*\b' + owner + r'\b', body):
            raise ValueError('RAII owner cleanup was bypassed')
        if re.search(r'\breturn\s+' + owner + r'\b|\b' + owner + r'\s*\.\s*(?:clone|to_owned)\s*\(', body):
            raise ValueError('Populated owner escaped its cleanup scope')


def audit_zeroizing_source(source):
    if source is None:
        raise ValueError('RAII cleanup implementation must be provided')
    code = _code(source)
    _, implementation = _item(code, r'\bimpl<T:\s*Zeroize>\s+Drop\s+for\s+Zeroizing<T>\s*\{')
    header, body = _method(implementation, 'drop')
    _same(header, 'fn drop(&mut self)', 'RAII Drop must borrow the owner')
    _same(body, 'self.0.zeroize();', 'RAII Drop must unconditionally zeroize its value')
    _, implementation = _item(code, r'\bimpl<T:\s*Zeroize,\s*const\s+N:\s*usize>\s+Zeroize\s+for\s+\[T;\s*N\]\s*\{')
    _, body = _method(implementation, 'zeroize')
    _same(body, 'self.as_mut_slice().zeroize();', 'Array cleanup must cover the whole slice')
    _, implementation = _item(code, r'\bimpl<T:\s*Zeroize>\s+Zeroize\s+for\s+\[T\]\s*\{')
    _, body = _method(implementation, 'zeroize')
    _same(body, '''T::zeroize_all(self);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);''',
          'Slice cleanup must cover all elements before its fence')
    _, implementation = _item(code, r'\bpub\s+trait\s+Zeroize\s*\{')
    _, body = _method(implementation, 'zeroize_all')
    _same(body, 'for x in all.iter_mut() { x.zeroize(); }',
          'Generic cleanup must visit every integer')
    # The existing macro supplies both widths used by powers and workspace.
    _, macro = _item(code, r'\bmacro_rules!\s+zeroize_primitive\s*\{')
    _, primitive_wipe = _method(macro, 'zeroize')
    _same(primitive_wipe, 'unsafe { core::ptr::write_volatile(self, 0) }',
          'Integer cleanup must unconditionally use the volatile zero store')
    if 'zeroize_primitive!(u16,u32,u64,u128,usize,i8);' not in _normal(code):
        raise ValueError('Both u64 and u128 volatile implementations must exist')
    return {'drop_unconditionally_zeroizes': True,
            'array_slice_all_elements_volatile': True,
            'normal_and_unwind_scope_policy': 'Rust lexical Drop; actual codegen checked separately',
            'zeroize_source_sha256': hashlib.sha256(source.encode()).hexdigest()}


def _guarded_api(source):
    code = _code(source)
    if not re.search(r'\bpub\s+const\s+PAYLOAD_LANES:\s*usize\s*=\s*50\s*;', code):
        raise ValueError('Guarded payload count must be fifty')
    declaration = re.search(r'\bpub\s+struct\s+PreparedPolynomial128x50\s*\{', code)
    if declaration is None:
        raise ValueError('Missing guarded retained preparation')
    adjacent = re.search(r'(?:#\[[^\]]*\]\s*)*$', code[:declaration.start()]).group()
    if re.search(r'\b(?:Clone|Copy)\b', adjacent) or re.search(r'\bimpl\s+(?:Clone|Copy)\s+for\s+PreparedPolynomial128x50', code):
        raise ValueError('Guarded prepared state must not acquire a value-copy route')
    _, fields = _item(code, r'\bpub\s+struct\s+PreparedPolynomial128x50\s*\{')
    _same(fields, 'planes: PreparedPolynomial128x64,', 'Guarded state must own only the exposed planes')
    _, implementation = _item(code, r'\bimpl\s+PreparedPolynomial128x50\s*\{')
    if re.search(r'\bfn\s+new\b', implementation):
        raise ValueError('Value-taking guarded constructor is forbidden')
    found = {}
    for name in ['empty', 'prepare', 'words_mut', 'copy_from']:
        header, body = _method(implementation, name)
        found[name] = _normal(header + '{' + body + '}')
    _same(found['empty'], 'fn empty() -> Self { Self { planes: PreparedPolynomial128x64::empty() } }',
          'Guarded empty must create only zero retained storage')
    header, body = _method(implementation, 'prepare')
    _same(header, 'fn prepare(&mut self, b: &[u128; PAYLOAD_LANES])',
          'Guarded prepare must borrow fifty raw inputs and return unit')
    if re.search(r'\b(?:return|clone|to_owned)\b|\*\s*b\b|\blet\b[^;=]*=\s*\[', body):
        raise ValueError('Guarded prepare introduced an aggregate copy/return')
    for plane in ['low', 'high', 'mixed']:
        if 'transpose_in_place(&mutself.planes.' + plane + '.0);' not in _normal(body):
            raise ValueError('All retained guarded planes must transpose in place')
    _same(found['words_mut'], 'fn words_mut(&mut self) -> [&mut [u64; 64]; 3] { self.planes.words_mut() }',
          'Guarded wipe exposure must delegate all three retained planes')
    _same(found['copy_from'], '''fn copy_from(&mut self, other: &Self) {
        self.planes.low.0.copy_from_slice(&other.planes.low.0);
        self.planes.high.0.copy_from_slice(&other.planes.high.0);
        self.planes.mixed.0.copy_from_slice(&other.planes.mixed.0);
    }''', 'Retained copies must borrow both owners with no aggregate temporary')
    for name in ['guarded_sum', 'clmul128x50_batch_xor_prepared']:
        header, body = _method(code, name)
        found[name] = _normal(header + '{' + body + '}')
    if not found['clmul128x50_batch_xor_prepared'].startswith(
            'fnclmul128x50_batch_xor_prepared(a:&[u128;PAYLOAD_LANES],b:&PreparedPolynomial128x50,working:&mutBatchWorking128x64,)'):
        raise ValueError('Guarded product must borrow raw blocks, prepared key and workspace')
    if not found['guarded_sum'].startswith(
            'fnguarded_sum(a:&mut[u64;64],b:&[u64;64],p:&mut[u64;128],out:&mutu128)'):
        raise ValueError('Guarded circuit operands/product/result must remain borrowed')
    return found


def audit_guarded_api(source, clean_source):
    if clean_source is None:
        raise ValueError('Committed clean guarded API must be provided')
    found = _guarded_api(source)
    if found != _guarded_api(clean_source):
        raise ValueError('Guarded ownership graph differs from committed clean-only code')
    return {'payload_lanes': 50, 'retained_u64_words': 192,
            'clean_api_expression_match': True,
            'graph_sha256': hashlib.sha256(repr(sorted(found.items())).encode()).hexdigest()}


def audit_guarded_preparation(source, caller, clean_source, zeroize_source):
    graph = audit_guarded_api(source, clean_source)
    cleanup = audit_zeroizing_source(zeroize_source)
    header, body = _method(_code(caller), 'prepare_powers')
    _same(header, 'fn prepare_powers(h: u128, prepared: &mut PreparedPolynomial128x50)',
          'Power helper must borrow its actual fifty-lane retained destination')
    _no_owner_escape(body, ['powers', 'power'])
    # Deliberately exact accepted scope: no early drop/forget, reassignment,
    # populated owner move, extra helper, or return bypasses this RAII policy.
    _same(body, '''
        let mut powers = Zeroizing::new([0u128; PAYLOAD_LANES]);
        let mut power = Zeroizing::new(0u128);
        *power = h;
        for slot in powers.iter_mut().rev() {
            *slot = *power;
            *power = mul::<false>(*power, h);
        }
        prepared.prepare(&powers);
    ''', 'Raw powers and running scalar require the reviewed zero-first RAII scope')
    _, drop_impl = _item(_code(caller), r'\bimpl\s+Drop\s+for\s+GhashKey\s*\{')
    _, drop_body = _method(drop_impl, 'drop')
    _same(drop_body, 'self.wipe();', 'Retained key Drop must invoke its full wipe')
    _, key_impl = _item(_code(caller), r'\bimpl\s+GhashKey\s*\{')
    _, wipe = _method(key_impl, 'wipe')
    _same(wipe, '''
        self.h.zeroize();
        if let Some(p) = self.powers.as_mut() { p.zeroize(); }
        #[cfg(target_pointer_width = "64")]
        if let Some(p) = self.portable_powers.as_mut() {
            for words in p.words_mut() { words.zeroize(); }
        }
    ''', 'Retained key must wipe all exposed guarded planes and existing key fields')
    return {'api': graph, 'cleanup': cleanup,
            'retained_key_drop_and_192_word_wipe': True,
            'raw_power_u128_words': 50, 'running_scalar_u128_words': 1,
            'zero_first_lexical_guards': True, 'source_owned_preparation_scratch_arrays': 0}


def audit_guarded_absorb(caller):
    header, body = _method(_code(caller), 'absorb_portable')
    _same(header, '''fn absorb_portable(h: u128, prepared: &PreparedPolynomial128x50,
        mut acc: u128, data: &[u8],) -> u128''', 'Guarded absorb must borrow its prepared key')
    _no_owner_escape(body, ['blocks', 'working'])
    _same(body, '''
        let mut batches = data.chunks_exact(PAYLOAD_LANES * 16);
        for batch in &mut batches {
            let mut blocks = Zeroizing::new([0u128; PAYLOAD_LANES]);
            for (block, bytes) in blocks.iter_mut().zip(batch.chunks_exact(16)) {
                *block = u128::from_be_bytes(bytes.try_into().unwrap()).reverse_bits();
            }
            blocks[0] ^= acc;
            {
                let mut working = Zeroizing::new(BatchWorking128x64::empty());
                clmul128x50_batch_xor_prepared(&blocks, prepared, &mut working);
                acc = reduce(working.output()[0], working.output()[1]);
            }
        }
        absorb::<false>(h, acc, batches.remainder())
    ''', 'Raw blocks and working state must stay guarded through their last borrowed use')
