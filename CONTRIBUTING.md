# Contributing to tcpform

Thank you for helping improve tcpform. Contributions of code, protocol
examples, documentation, bug reports, and design feedback are welcome.

## Before you start

- Search existing issues and pull requests before opening a duplicate.
- Use an issue for bugs and self-contained feature requests.
- Start a discussion before making a large DSL, architecture, or compatibility
  change so the design can be agreed before implementation.
- Security vulnerabilities must be reported according to [SECURITY.md](SECURITY.md),
  not through a public issue.

## Development setup

tcpform requires Rust 1.88 or newer. Node.js 20 and Docker are only needed for
the browser and container test suites.

```sh
git clone https://github.com/penguin425/tcpform-protocol-lab.git
cd tcpform-protocol-lab
cargo build --locked
cargo test --lib --bins --locked
cargo test --test integration --locked -- --test-threads=1
cargo test --test property --locked
```

Before submitting a pull request, also run:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
```

For dashboard changes:

```sh
npm ci
npm run test:e2e
```

## Making a change

1. Create a focused branch from the latest `main`.
2. Keep commits small and use a descriptive imperative commit message.
3. Add or update tests for behavior changes.
4. Update README examples and `CHANGELOG.md` when users will notice the change.
5. Open a pull request using the repository template.

The `main` branch requires signed commits, an up-to-date branch, resolved review
conversations, and a successful `CI success` check. Pull requests are squash
merged, so the pull request title should also make a useful changelog entry.

## Compatibility expectations

- Avoid breaking the `.tcpf` DSL, JSON schema, bundle format, and CLI without a
  documented migration path.
- New serialized formats must include an explicit version.
- Keep deterministic simulations and tests independent of host scheduling where
  possible.
- Preserve Linux, macOS, and Windows support. Guard platform-specific behavior
  with appropriate `cfg` attributes.
- Do not commit secrets, private packet captures, credentials, or identifying
  traffic data. Use the anonymization tooling before sharing reproductions.

## Reporting a bug

Include the tcpform version, operating system, minimal `.tcpf` input, command,
expected behavior, actual behavior, and any sanitized trace or reproduction
bundle. A small reproducible case is more valuable than a large production
capture.

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

