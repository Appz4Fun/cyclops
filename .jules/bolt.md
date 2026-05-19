## 2024-05-24 - Speed up yEnc decoding in Python
**Learning:** Python's native `bytearray` iteration (`for byte in bytes:`) and index access is extremely slow compared to native C extensions. By utilizing `bytes.translate()` and `bytes.find()`, one can push the entire loop into C, even when the logic requires conditional parsing (like yEnc's `=`).
**Action:** When working with large byte payloads in pure Python (like NNTP downloads or parsing), always prefer vectorized operations like `.translate()`, `.split()`, `.find()` over pure python character iteration.
