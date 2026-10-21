# cryptography-grind

Applied cryptography, learned by building: from-scratch implementations, attacks and benchmarks, each with tests and a short
write-up. Follows *Understanding Cryptography* (Paar & Pelzl) as set in an internship assignment series.

> **Educational code.** Hand-written ciphers are slow and not hardened against side channels. Never protect real data with
> them; use a vetted library. Attacks here run only against toy targets built for the exercise.
> Built with [Claude Code](https://claude.ai/code); every solution is tested and the write-ups use measured numbers.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest                          # run all tests
python -m cryptolab.ch01.frequency_attack   # every module has a runnable demo
```

## Progress (code assignments)

| Chapter | Assignments | Write-up | Status |
|---|---|---|---|
| 1 Introduction | 1.1 frequency attack, 1.4 brute-force calculator | [ch01](docs/ch01.md) | done |
| 2 Stream ciphers | 2.1 OTP, 2.2 LFSR + Berlekamp-Massey, 2.4 keystream reuse | [ch02](docs/ch02.md) | done |
| 3 DES | 3.1 Feistel trace, 3.2 meet-in-the-middle, 3.4 brute force, 3.5 3DES vs AES | [ch03](docs/ch03.md) | done |
| 4 AES | 4.1 round trace, 4.2 NIST vectors, 4.4 AES-NI benchmark, 4.5 file-encryption CLI | [ch04](docs/ch04.md) | done |
| 5 Block-cipher modes | 5.1 ECB penguin, 5.3 GCM + tamper, 5.5 TLS audit, 5.6 secure log | [ch05](docs/ch05.md) | done |
| 6-13 | in progress | | |
