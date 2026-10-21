# UpdateKit roadmap

## Next

- **Apply helper**: a staged hand-off — launch a detached helper that
  waits for the app to exit, swaps the package contents in, relaunches,
  and rolls back on failure. This is the piece v0.1 deliberately left
  to apps; it needs the most care (permissions, locked files, partial
  extraction) and lands as its own reviewed slice.
- **Channels & per-arch packages**: manifest v2 with a `packages` map
  keyed by arch/channel, selected by the DLL.
- **Authenticode check**: optional `uk_verify_signature(path)` using
  WinVerifyTrust, so a package can be required to be signed by a
  named publisher in addition to matching the manifest hash.

## Later

- Resumable downloads (Range requests) for very large packages.
- Delta updates once there's a measured size problem to solve.
- Manifest signing (detached signature over the manifest itself) for
  hosts that cannot guarantee HTTPS.

## Non-goals

- No background service or scheduled silent updates — the app decides
  when to check and when to ask the user.
- No package authoring: building the update archive is ArchiveKit's /
  the app's release pipeline's job.
