# JitterChaChaRng

**A high-entropy, CPU-jitter-based random number generator in C# using ChaCha20.**

---

## Overview

`JitterChaChaRng` is a proof-of-concept cryptographically-inspired random number generator (RNG) that combines:

- **CPU timing jitter** (via high-resolution timestamps or optional Windows RDTSC)
- **ChaCha20 stream cipher** for fast, software-based keystream generation
- **OS RNG mixing** for additional entropy
- **Entropy health monitoring** to detect low-entropy conditions in real-time

This approach aims to produce **non-deterministic random data** for cryptographic or experimental purposes, particularly when traditional entropy sources are limited or unavailable.

> ⚠️ **Warning:** This is not FIPS-certified and is intended for research, learning, and experimentation. Do **not** rely solely on this RNG for production-grade cryptographic keys without proper threat analysis and additional entropy sources.

---

## Features

- Pure C# implementation, easy to run on Windows, Linux, and macOS.
- Optional **native RDTSC DLL** for high-resolution CPU timestamp reading on Windows.
- ChaCha20 used instead of AES-CTR for simplicity and software efficiency.
- Periodic **entropy health checks**:
  - LSB bias
  - Sample variance
  - Repeated-value detection
  - Unique byte counts
- Automatic reseeding after generating 1 MB of output.
- Mixing with OS RNG for additional robustness.

---

## Requirements

- .NET 6.0 or newer SDK
- Visual Studio Code (optional, recommended)
- Optional for Windows native timing: `rdtsc.dll` (build from `rdtsc.c`)

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/JitterChaChaRng.git
cd JitterChaChaRng
# rngcsharp
random number production using cpu jitter
