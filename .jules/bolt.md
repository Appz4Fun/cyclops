## 2024-05-20 - Fast yEnc Decoding in Python
**Learning:** Character-by-character decoding in Python (`while` loop over bytes) is a massive performance bottleneck for yEnc decoding, taking ~0.8s per 360KB.
**Action:** Use `bytes.split(b'=')` to isolate escapes and `bytes.translate(table)` to decode the unescaped chunks in C-space. This bypasses Python-level loop overhead, dropping decoding time to ~0.013s (a 60x speedup).
