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
| 3 DES | 3.1, 3.2, 3.4, 3.5 | | in progress |
| 4 AES | 4.1, 4.2, 4.4, 4.5 | | |
| 5-13 | see the plan in the repo issues | | |
