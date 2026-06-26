# reverSSH

`reverSSH` is a dependency-less Python reverse SSH relay and client.

The operator connects with OpenSSH:

```sh
ssh -p 2222 identifier@relay-host
```

The remote machine, which may be behind NAT, connects outward:

```sh
reverssh-client --relay relay-host:8022 --identifier identifier
```

The relay terminates SSHv2 for OpenSSH clients and routes approved session,
SFTP, and forwarding channels to the registered reverse client over a private
length-prefixed protocol. The relay does not execute commands or access files on
the remote machine.

## Run

Start the relay:

```sh
reverssh-relay \
  --ssh-listen 0.0.0.0:2222 \
  --client-listen 0.0.0.0:8022 \
  --state-dir ./state
```

Start a reverse client:

```sh
reverssh-client \
  --relay relay-host:8022 \
  --identifier laptop \
  --state-dir ~/.reverssh
```

If the relay exposes its reverse-client protocol through a WebSocket endpoint,
use that URL instead:

```sh
reverssh-client \
  --relay wss://dev.tsuku.re/reverssh-client/ \
  --identifier laptop \
  --state-dir ~/.reverssh
```

For throwaway environments with Python 3.11+, the hosted bootstrap script can
download the client and run it in the foreground:

```sh
curl -fsSL https://dev.tsuku.re/reverssh-client.sh | bash
```

Useful overrides:

```sh
REVERSH_IDENTIFIER=mybox curl -fsSL https://dev.tsuku.re/reverssh-client.sh | bash
REVERSH_STATE_DIR=/tmp/reverssh curl -fsSL https://dev.tsuku.re/reverssh-client.sh | bash
REVERSH_OPERATOR_KEYS="$(cat ~/.ssh/id_ed25519.pub)" curl -fsSL https://dev.tsuku.re/reverssh-client.sh | bash
```

Then connect as the operator:

```sh
ssh -p 2222 laptop@relay-host
sftp -P 2222 laptop@relay-host
ssh -p 2222 -L 9000:127.0.0.1:80 laptop@relay-host
ssh -p 2222 -R 9001:127.0.0.1:8080 laptop@relay-host
```

## Trust

The relay verifies that the OpenSSH operator proves possession of an
`ssh-ed25519` private key. It then forwards the operator key fingerprint to the
reverse client. The reverse client approves trusted fingerprints from
`~/.reverssh/known_operators`, or prompts interactively for one-time or
persistent trust.

Persistent operator trust is stored on the reverse client side, not on the relay.

For non-interactive environments, set `REVERSH_OPERATOR_KEYS` to one or more
colon-separated OpenSSH public keys. When this env var is set, the client runs
in strict allowlist mode: it never prompts, ignores `known_operators` for
authorization, and accepts only operators whose public key exactly matches the
env allowlist.

```sh
export REVERSH_OPERATOR_KEYS="$(cat ~/.ssh/id_ed25519.pub)"
reverssh-client --relay wss://dev.tsuku.re/reverssh-client/ --identifier mybox
```

## Compatibility

The intentionally small SSH algorithm set is:

- KEX: `curve25519-sha256`, `curve25519-sha256@libssh.org`
- Host and user keys: `ssh-ed25519`
- Cipher: `chacha20-poly1305@openssh.com`
- Compression: `none`

Runtime dependencies are limited to the Python standard library. The crypto
primitives required by that SSH subset are implemented in `reverssh/crypto` and
covered by known-answer tests.

## Test

```sh
python -m unittest discover -s tests
```

## License

MIT
