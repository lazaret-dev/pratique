#!/usr/bin/env python3
"""Owned-source structural regressions; never executes the crypto/test ELF.

Mutants are in-memory source fixtures, not edits to production. The small legacy
caller fixture exercises the old structural contract without requiring Git
history (the restricted private worker creates a synthetic checkout).
"""
import unittest
import shutil
import tempfile
from unittest.mock import patch
from pathlib import Path

from preparation_lifecycle import audit_preparation_source
from working_state_lifecycle import audit_working_source

ROOT = Path(__file__).resolve().parents[2]
LEGACY_CALLER = '''
impl Zeroize for BatchWorking128x64 {
    fn zeroize(&mut self) {
        for words in self.words64_mut() { words.zeroize(); }
        for words in self.words128_mut() { words.zeroize(); }
    }
}
fn prepare_powers(h: u128, prepared: &mut PreparedPolynomial128x64) {
    let mut powers = [0u128; 64]; let mut power = h;
    prepared.prepare(&powers); powers.zeroize(); power.zeroize();
}
impl GhashKey {
    fn new() -> GhashKey {
        let mut key = GhashKey { portable_powers: Some(PreparedPolynomial128x64::empty()) };
        if let Some(prepared) = key.portable_powers.as_mut() { prepare_powers(0, prepared); }
        key
    }
}
fn absorb_portable() {
    let mut blocks = Zeroizing::new([0u128; 64]);
    let mut working = Zeroizing::new(BatchWorking128x64::empty());
    clmul128_batch_xor_prepared(&blocks, prepared, &mut working);
    acc = reduce(working.output()[0], working.output()[1]);
}
'''


class LifecycleAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        read = lambda path: (ROOT / path).read_text()
        cls.production = read('src/crypto/clmul_batch_clean.rs')
        cls.caller = read('src/crypto/ghash.rs')
        cls.clean = read('cleanroom/clmul_feasibility/lib.rs')
        cls.circuit = read('src/crypto/clmul_batch_circuit.rs')
        cls.guarded = read('src/crypto/clmul_batch_clean/guarded.rs')
        cls.clean_guarded = read('cleanroom/clmul_feasibility/guarded.rs')
        cls.zeroize = read('src/zeroize.rs')

    def check_graph(self, caller=None, guarded=None, clean_guarded=None, zeroize=None):
        options = dict(guarded_source=self.guarded if guarded is None else guarded,
                       clean_guarded_source=self.clean_guarded if clean_guarded is None else clean_guarded,
                       zeroize_source=self.zeroize if zeroize is None else zeroize)
        caller = self.caller if caller is None else caller
        a = audit_preparation_source(self.production, caller, self.clean, **options)
        b = audit_working_source(self.production, caller, self.clean, self.circuit, **options)
        self.assertEqual(a['guarded_50_lane_preparation']['raw_power_u128_words'], 50)
        self.assertEqual(b['raw_block_u128_words'], 50)
        self.assertEqual((b['workspace_u64_words'], b['workspace_u128_words']), (320, 5))

    def mutant(self, text, old, new):
        self.assertIn(old, text, 'Mutant did not bind the current source')
        changed = text.replace(old, new, 1)
        self.assertNotEqual(changed, text)
        return changed

    def reject_caller(self, old, new):
        with self.assertRaises(ValueError):
            self.check_graph(caller=self.mutant(self.caller, old, new))

    def test_current_guarded_graph(self):
        self.check_graph()

    def test_legacy_preparation_and_working_graph(self):
        a = audit_preparation_source(self.production, LEGACY_CALLER, self.clean)
        b = audit_working_source(self.production, LEGACY_CALLER, self.clean, self.circuit)
        self.assertIsNone(a['guarded_50_lane_preparation'])
        self.assertEqual(b['raw_block_u128_words'], 64)

    def test_legacy_explicit_power_cleanup_is_still_required(self):
        for wipe in ['powers.zeroize();', 'power.zeroize();']:
            with self.subTest(wipe=wipe), self.assertRaises(ValueError):
                audit_preparation_source(self.production, LEGACY_CALLER.replace(wipe, ''), self.clean)

    def test_legacy_workspace_cleanup_is_still_required(self):
        with self.assertRaises(ValueError):
            audit_working_source(self.production, LEGACY_CALLER.replace('self.words128_mut()', 'self.words64_mut()'), self.clean, self.circuit)

    def test_legacy_by_value_input_rejected_even_if_clean_copy_also_changed(self):
        broken = self.mutant(self.production, 'b: &[u128; 64]', 'b: [u128; 64]')
        clean = self.mutant(self.clean, 'b: &[u128; 64]', 'b: [u128; 64]')
        with self.assertRaises(ValueError):
            audit_preparation_source(broken, LEGACY_CALLER, clean)

    def test_guarded_by_value_powers_rejected_even_if_clean_copy_also_changed(self):
        old, new = 'b: &[u128; PAYLOAD_LANES]', 'b: [u128; PAYLOAD_LANES]'
        with self.assertRaises(ValueError):
            self.check_graph(guarded=self.mutant(self.guarded, old, new), clean_guarded=self.mutant(self.clean_guarded, old, new))

    def test_guarded_by_value_blocks_rejected_even_if_clean_copy_also_changed(self):
        old, new = 'a: &[u128; PAYLOAD_LANES]', 'a: [u128; PAYLOAD_LANES]'
        with self.assertRaises(ValueError):
            self.check_graph(guarded=self.mutant(self.guarded, old, new), clean_guarded=self.mutant(self.clean_guarded, old, new))

    def test_guarded_populated_return_rejected(self):
        old = 'pub fn prepare(&mut self, b: &[u128; PAYLOAD_LANES]) {'
        new = old[:-1] + '-> Self {'
        with self.assertRaises(ValueError):
            self.check_graph(guarded=self.mutant(self.guarded, old, new))

    def test_guarded_copy_input_rejected(self):
        old = 'pub fn prepare(&mut self, b: &[u128; PAYLOAD_LANES]) {'
        with self.assertRaises(ValueError):
            self.check_graph(guarded=self.mutant(self.guarded, old, old + ' let scratch = *b;'))

    def test_missing_committed_guarded_copy_rejected(self):
        with self.assertRaises(ValueError):
            audit_preparation_source(self.production, self.caller, self.clean, self.guarded, None, self.zeroize)

    def test_power_destination_must_be_borrowed(self):
        self.reject_caller('prepared: &mut PreparedPolynomial128x50', 'prepared: PreparedPolynomial128x50')

    def test_power_array_guard_required(self):
        self.reject_caller('let mut powers = Zeroizing::new([0u128; PAYLOAD_LANES]);', 'let mut powers = [0u128; PAYLOAD_LANES];')

    def test_running_scalar_guard_required(self):
        self.reject_caller('let mut power = Zeroizing::new(0u128);', 'let mut power = 0u128;')

    def test_array_guard_cannot_be_populated_before_move(self):
        self.reject_caller('let mut powers = Zeroizing::new([0u128; PAYLOAD_LANES]);', 'let mut powers = Zeroizing::new([h; PAYLOAD_LANES]);')

    def test_raw_preparation_call_must_borrow(self):
        self.reject_caller('prepared.prepare(&powers);', 'prepared.prepare(*powers);')

    def test_forget_guard_rejected(self):
        self.reject_caller('prepared.prepare(&powers);', 'prepared.prepare(&powers); core::mem::forget(powers);')

    def test_moved_guard_rejected(self):
        self.reject_caller('prepared.prepare(&powers);', 'prepared.prepare(&powers); let moved = powers;')

    def test_early_drop_or_shortened_guard_scope_rejected(self):
        self.reject_caller('prepared.prepare(&powers);', 'drop(powers); prepared.prepare(&powers);')

    def test_prepare_early_return_rejected(self):
        self.reject_caller('prepared.prepare(&powers);', 'return; prepared.prepare(&powers);')

    def test_blocks_guard_required(self):
        self.reject_caller('let mut blocks = Zeroizing::new([0u128; PAYLOAD_LANES]);', 'let mut blocks = [0u128; PAYLOAD_LANES];')

    def test_work_guard_required(self):
        self.reject_caller('let mut working = Zeroizing::new(BatchWorking128x64::empty());', 'let mut working = BatchWorking128x64::empty();')

    def test_work_guard_must_cover_last_output_use(self):
        self.reject_caller('acc = reduce(working.output()[0], working.output()[1]);', 'drop(working); acc = reduce(working.output()[0], working.output()[1]);')

    def test_guarded_raw_block_count_must_remain_fifty(self):
        self.reject_caller('let mut blocks = Zeroizing::new([0u128; PAYLOAD_LANES]);', 'let mut blocks = Zeroizing::new([0u128; 64]);')

    def test_working_wipe_covers_u128_fields(self):
        self.reject_caller('self.words128_mut()', 'self.words64_mut()')

    def test_retained_key_drop_is_required(self):
        self.reject_caller('self.wipe();', '')

    def test_retained_key_plane_cleanup_is_required(self):
        self.reject_caller('for words in p.words_mut() {\n                words.zeroize();\n            }', '')

    def test_raii_drop_not_just_normal_explicit_cleanup(self):
        broken = self.mutant(self.zeroize, 'self.0.zeroize();', '')
        with self.assertRaises(ValueError):
            self.check_graph(zeroize=broken)

    def test_array_cleanup_covers_all_elements(self):
        broken = self.mutant(self.zeroize, 'self.as_mut_slice().zeroize();', '')
        with self.assertRaises(ValueError):
            self.check_graph(zeroize=broken)

    def test_conditional_volatile_store_rejected(self):
        broken = self.mutant(self.zeroize, 'unsafe { core::ptr::write_volatile(self, 0) }',
                             'if false { unsafe { core::ptr::write_volatile(self, 0) } }')
        with self.assertRaises(ValueError):
            self.check_graph(zeroize=broken)

    def test_main_missing_guarded_file_fails_before_compiler(self):
        import audit_primitives
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            p = root / 'src/crypto/ghash.rs'
            p.parent.mkdir(parents=True)
            p.write_text(self.caller)
            with patch.object(audit_primitives, 'ROOT', root), patch('sys.argv', ['audit_primitives.py']), self.assertRaises(FileNotFoundError):
                audit_primitives.main()

    def test_main_missing_guard_constants_fails_before_compiler(self):
        import audit_primitives
        paths = [
            'src/crypto/ghash.rs', 'src/crypto/clmul_batch_clean.rs',
            'src/crypto/clmul_batch_circuit.rs', 'src/crypto/clmul_batch_clean/guarded.rs',
            'src/crypto/aes_sbox_tower_clean.rs', 'src/zeroize.rs',
            'cleanroom/clmul_feasibility/lib.rs', 'cleanroom/clmul_feasibility/circuit.rs',
            'cleanroom/clmul_feasibility/guarded.rs', 'cleanroom/aes_tower/sbox.rs',
        ]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for relative in paths:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            with patch.object(audit_primitives, 'ROOT', root), patch('sys.argv', ['audit_primitives.py']), self.assertRaises(FileNotFoundError):
                audit_primitives.main()

    def test_volatile_store_is_required(self):
        broken = self.mutant(self.zeroize, 'core::ptr::write_volatile(self, 0)', 'core::ptr::write(self, 0)')
        with self.assertRaises(ValueError):
            self.check_graph(zeroize=broken)


if __name__ == '__main__':
    unittest.main()
