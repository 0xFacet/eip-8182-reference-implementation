# Keccak256 Hashing Library

This package contains the Keccak256 hashing interface, formerly in the Noir standard library.

## Noir Version Compatibility

This library requires Noir **v1.0.0** or later.

## Installation

In `Nargo.toml`, add the version of this library you want to install:

```toml
[dependencies]
keccak256 = { tag = "v0.1.2", git = "https://github.com/noir-lang/keccak256" }
```

## Usage

```rust
use dep::keccak256::keccak256;

fn main() {
    let input = "Hello world!".as_bytes();
    let hash = keccak256(input, input.len());
    // hash is [u8; 32]
}
```

## Testing

### Unit Tests

Run the standard unit tests:

```bash
nargo test
```

### Oracle-Based Property Tests

The library includes property-based tests that verify correctness against a reference implementation via an oracle server:

```bash
# Run tests with oracle server (from scripts directory)
cd scripts
./run.sh
```

The oracle tests use a TypeScript server to provide reference Keccak256 implementations, testing various input sizes (1, 100, 135, and 256 bytes) with random inputs.

## Benchmarks

Benchmarks are ignored by `git` and checked on pull requests. Generate the benchmark report with:

```bash
nargo export
./scripts/build-gates-report.sh
./scripts/build-brillig-report.sh
```

The benchmark will be generated at `./gates_report.json` and `./brillig_report.json`.
