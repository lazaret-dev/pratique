#!/usr/bin/env python3
"""Writes tests/data/punycode_vectors.txt: the 19 sample strings of RFC 3492 section 7.1 (code points and encodings as the
RFC gives them, each checked against Python's 'punycode' codec when this runs), then 200 random strings from several
scripts and planes encoded by that codec, and the empty string. Run from the repository root:
python3 tools/gen_punycode_vectors.py (the output is the same every time: the random generator is seeded)."""
import random

RFC_3492_SAMPLES = [
    'A Arabic (Egyptian) | u+0644 u+064A u+0647 u+0645 u+0627 u+0628 u+062A u+0643 u+0644 u+0645 u+0648 u+0634 u+0639 u+0631 u+0628 u+064A u+061F | egbpdaj6bu4bxfgehfvwxn',
    'B Chinese (simplified) | u+4ED6 u+4EEC u+4E3A u+4EC0 u+4E48 u+4E0D u+8BF4 u+4E2D u+6587 | ihqwcrb4cv8a8dqg056pqjye',
    'C Chinese (traditional) | u+4ED6 u+5011 u+7232 u+4EC0 u+9EBD u+4E0D u+8AAA u+4E2D u+6587 | ihqwctvzc91f659drss3x8bo0yb',
    'D Czech | U+0050 u+0072 u+006F u+010D u+0070 u+0072 u+006F u+0073 u+0074 u+011B u+006E u+0065 u+006D u+006C u+0075 u+0076 u+00ED u+010D u+0065 u+0073 u+006B u+0079 | Proprostnemluvesky-uyb24dma41a',
    'E Hebrew | u+05DC u+05DE u+05D4 u+05D4 u+05DD u+05E4 u+05E9 u+05D5 u+05D8 u+05DC u+05D0 u+05DE u+05D3 u+05D1 u+05E8 u+05D9 u+05DD u+05E2 u+05D1 u+05E8 u+05D9 u+05EA | 4dbcagdahymbxekheh6e0a7fei0b',
    'F Hindi (Devanagari) | u+092F u+0939 u+0932 u+094B u+0917 u+0939 u+093F u+0928 u+094D u+0926 u+0940 u+0915 u+094D u+092F u+094B u+0902 u+0928 u+0939 u+0940 u+0902 u+092C u+094B u+0932 u+0938 u+0915 u+0924 u+0947 u+0939 u+0948 u+0902 | i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd',
    'G Japanese (kanji and hiragana) | u+306A u+305C u+307F u+3093 u+306A u+65E5 u+672C u+8A9E u+3092 u+8A71 u+3057 u+3066 u+304F u+308C u+306A u+3044 u+306E u+304B | n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa',
    'H Korean (Hangul syllables) | u+C138 u+ACC4 u+C758 u+BAA8 u+B4E0 u+C0AC u+B78C u+B4E4 u+C774 u+D55C u+AD6D u+C5B4 u+B97C u+C774 u+D574 u+D55C u+B2E4 u+BA74 u+C5BC u+B9C8 u+B098 u+C88B u+C744 u+AE4C | 989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a0dt30a5jpsd879ccm6fea98c',
    'I Russian (Cyrillic) | U+043F u+043E u+0447 u+0435 u+043C u+0443 u+0436 u+0435 u+043E u+043D u+0438 u+043D u+0435 u+0433 u+043E u+0432 u+043E u+0440 u+044F u+0442 u+043F u+043E u+0440 u+0443 u+0441 u+0441 u+043A u+0438 | b1abfaaepdrnnbgefbaDotcwatmq2g4l',
    'J Spanish | U+0050 u+006F u+0072 u+0071 u+0075 u+00E9 u+006E u+006F u+0070 u+0075 u+0065 u+0064 u+0065 u+006E u+0073 u+0069 u+006D u+0070 u+006C u+0065 u+006D u+0065 u+006E u+0074 u+0065 u+0068 u+0061 u+0062 u+006C u+0061 u+0072 u+0065 u+006E U+0045 u+0073 u+0070 u+0061 u+00F1 u+006F u+006C | PorqunopuedensimplementehablarenEspaol-fmd56a',
    'K Vietnamese | U+0054 u+1EA1 u+0069 u+0073 u+0061 u+006F u+0068 u+1ECD u+006B u+0068 u+00F4 u+006E u+0067 u+0074 u+0068 u+1EC3 u+0063 u+0068 u+1EC9 u+006E u+00F3 u+0069 u+0074 u+0069 u+1EBF u+006E u+0067 U+0056 u+0069 u+1EC7 u+0074 | TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g',
    'L Japanese (artist names, example L) | u+0033 u+5E74 U+0042 u+7D44 u+91D1 u+516B u+5148 u+751F | 3B-ww4c5e180e575a65lsy2b',
    'M Japanese (example M) | u+5B89 u+5BA4 u+5948 u+7F8E u+6075 u+002D u+0077 u+0069 u+0074 u+0068 u+002D U+0053 U+0055 U+0050 U+0045 U+0052 u+002D U+004D U+004F U+004E U+004B U+0045 U+0059 U+0053 | -with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n',
    'N Japanese (example N) | U+0048 u+0065 u+006C u+006C u+006F u+002D U+0041 u+006E u+006F u+0074 u+0068 u+0065 u+0072 u+002D U+0057 u+0061 u+0079 u+002D u+305D u+308C u+305E u+308C u+306E u+5834 u+6240 | Hello-Another-Way--fc4qua05auwb3674vfr0b',
    'O Japanese (example O) | u+3072 u+3068 u+3064 u+5C4B u+6839 u+306E u+4E0B u+0032 | 2-u9tlzr9756bt3uc0v',
    'P Japanese (example P) | U+004D u+0061 u+006A u+0069 u+3067 U+004B u+006F u+0069 u+3059 u+308B u+0035 u+79D2 u+524D | MajiKoi5-783gue6qz075azm5e',
    'Q Japanese (example Q) | u+30D1 u+30D5 u+30A3 u+30FC u+0064 u+0065 u+30EB u+30F3 u+30D0 | de-jg4avhby1noc0d',
    'R Japanese (example R) | u+305D u+306E u+30B9 u+30D4 u+30FC u+30C9 u+3067 | d9juau41awczczp',
    'S ASCII example | u+002D u+003E u+0020 u+0024 u+0031 u+002E u+0030 u+0030 u+0020 u+003C u+002D | -> $1.00 <--',
]

lines = [
    "# Punycode (RFC 3492): code points (hex, space-separated; '-' for none) TAB the encoding.",
    "# The 19 samples of RFC 3492 section 7.1 (an uppercase letter in an encoding is the RFC's mixed-case annotation,",
    "# which a decoder ignores), then random strings encoded by Python's 'punycode' codec. tools/gen_punycode_vectors.py.",
]
for line in RFC_3492_SAMPLES:
    label, cps, puny = [x.strip() for x in line.split("|")]
    s = "".join(chr(int(c[2:], 16)) for c in cps.split())
    assert s.encode("punycode").decode().lower() == puny.lower(), label
    lines.append(" ".join(c[2:].lower() for c in cps.split()) + "\t" + puny)
random.seed(20261007)
ranges = [(0x61, 0x7a), (0x30, 0x39), (0x2d, 0x2d), (0xe0, 0xff), (0x100, 0x17f), (0x3b1, 0x3c9), (0x430, 0x44f), (0x621, 0x64a),
          (0x905, 0x939), (0x4e00, 0x9fff), (0xac00, 0xd7a3), (0x3041, 0x3096), (0x1f600, 0x1f64f), (0x10400, 0x1044f)]
for i in range(200):
    n = random.randint(1, 30)
    k = random.sample(ranges, random.randint(1, 3))
    s = "".join(chr(random.randint(*random.choice(k))) for _ in range(n))
    lines.append(" ".join("%x" % ord(c) for c in s) + "\t" + s.encode("punycode").decode())
lines.append("-\t")
open("tests/data/punycode_vectors.txt", "w").write("\n".join(lines) + "\n")
print("wrote tests/data/punycode_vectors.txt (%d vectors)" % (len(lines) - 3))
