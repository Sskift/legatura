# Brownfield app/apk/relay reference

This fixed reference shows how an existing repository can adopt Legatura without
pretending that every part of the system already has the same assurance level.
It is ordinary Project Model input; there is no brownfield-only schema or
adoption command.

- `relay` is governed and owns the only executable acceptance proof.
- `app` and `apk` are independent provisional providers. `relay` can see their
  public Contracts, but its initial compiled read scope does not include their
  implementation paths.
- `legacy/device-bridge.mjs` remains deliberately unmodeled. The Project Model
  records it as opaque, and `legacy/**` is assigned to an explicit ungoverned
  disposition that grants no write authority.
- `repository-governance` owns this README and `.legatura/**` so later adoption
  Changes can evolve governance through an ordinary owned Module boundary.

Run the reference proof from this directory:

```sh
node --test relay/relay.proof.mjs
```

The proof injects a fake delivery port. It never imports `app/public.mjs`,
`apk/public.mjs`, or the legacy implementation. That demonstrates the intended
Contract seam; it does not claim operating-system sandbox enforcement.
