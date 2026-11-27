# Architecture (v0.1 core)

```text
CLI
 ├── receive
 └── send
       |
       v
Transfer orchestration
       |
       +-- pairing: 256-bit one-session PSK
       |
       +-- protocol: Noise NNpsk0 transport over TCP
       |
       +-- metadata validation: name, extension, declared size
       |
       +-- streaming: 32 KiB bounded chunks
       |
       +-- integrity: SHA-256
       |
       +-- safe commit: temporary file + no-overwrite hard-link
```

## Session lifecycle

1. Receiver binds only after an explicit `receive` command.
2. Receiver generates a cryptographically random 256-bit PSK.
3. Receiver displays a Base32 code and opens a five-minute pairing window.
4. Sender connects to the entered LAN endpoint and performs a Noise `NNpsk0` handshake. The receiver polls its listener until the pairing deadline; each accepted socket is explicitly switched back to blocking mode before handshake I/O, then receives bounded read/write timeouts. The handshake and encrypted PSK confirmation share a 12-second absolute deadline; partial reads or writes cannot extend it by trickling bytes.
5. Sender proves possession of the PSK with an encrypted transport message; receiver accepts only the matching proof. A handshake that completes after the five-minute pairing expiry is rejected.
6. Sender transmits file metadata. Receiver validates the basename, extension, and size and asks for local user approval.
7. File content is streamed in 32 KiB chunks. Receiver writes only to a newly created temporary file in the selected destination directory.
8. Both sides calculate SHA-256. Receiver commits only after declared size and digest match.
9. The final file is created without overwriting an existing file. A collision is handled by adding a numeric suffix.

## Threat boundaries

- The pairing code is a bearer secret. Anyone who obtains it can attempt to connect during that receive session.
- The one-time code authenticates possession of the code, not a long-term device identity. Persistent device identity and trust management are future work.
- A local attacker can still deny service by exhausting the receiver's bounded invalid-connection attempts or by disrupting the network. The absolute handshake deadline limits how long one unauthenticated peer can hold an accepted socket, but it does not eliminate LAN-level denial of service.
- This implementation does not scan file contents for malware and does not claim to do so.
- File-extension validation is only a policy gate; it is not content-type verification.
- The receiver's user confirmation is mandatory for each file.
- The protocol implementation has not undergone an independent security audit.
