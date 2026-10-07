# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-page browser demo for a class assignment. It takes an ISO certificate (form fields or JSON), generates real issuer and holder DIDs, builds a **W3C VC Data Model v2.0** credential, signs it with a `DataIntegrityProof`, and verifies it (including VCs uploaded from elsewhere). It is the first step toward a Digital Product Passport (DPP). UI text, comments and docs are in Traditional Chinese (zh-Hant). Keep new user-facing strings in zh-Hant.

The user asked to **use built-in or existing crypto rather than reimplementing it**:
- **did:key** (Ed25519) signs with the W3C-standard `eddsa-jcs-2022` cryptosuite. It uses only the browser's WebCrypto, so it works offline.
- **did:ethr on Sepolia** (secp256k1) signs with `ecdsa-secp256k1-recovery-jcs-demo`. That cryptosuite is a **custom, non-standard teaching suite**: it uses the same hashData as eddsa-jcs-2022, then signs SHA-256(hashData) and stores proofValue as 65 bytes r‖s‖recId(0/1).
  - Verification recovers the signer's address, then resolves the issuer's DID document with the official **`ethr-did-resolver`**, which reads events from the existing ERC-1056 registry on Sepolia (`0x03d5003bf0e79C5F5223588F347ebA39AfbC3818`, chainId 11155111). It then finds the key that the proof's `verificationMethod` fragment points to (`#controller` or `#delegate-N`), requires that key to be listed in `assertionMethod`, and compares addresses. Revoked or expired delegates and deactivated DIDs therefore fail.
  - If the RPC is unreachable (resolver returns `internalError`), it falls back to the default doc, where `#controller` is the DID's own address, and reports a warning.
  - secp256k1, keccak and EIP-55 come from **ethers.js v6**, loaded from cdnjs with an SRI hash. The resolver is `import()`ed lazily from jsdelivr `+esm` (`ETHR.resolverModules`, pinned to `did-resolver@5.0.1` + `ethr-did-resolver@14.1.4`; ethr-did-resolver 14 needs did-resolver 5, not 6).
- **RPC gotcha**: resolution reads *old* event logs. `ethereum-sepolia-rpc.publicnode.com` prunes logs older than ~10k blocks, so old delegates silently disappear. The default is `https://sepolia.gateway.tenderly.co`, which is free, CORS-enabled and keeps historical logs. drpc's free tier rejects Sepolia, 1rpc limits getLogs to 50 blocks, and blastapi/blockpi/omniatech lack CORS.
- Roadmap: step 1 (read-only DID resolution) is done, and step 2 (MetaMask writes) is implemented.
  - In step 2, the MetaMask account is the issuer DID and an in-page key is its `veriKey` delegate. The issuer key object is `{ viaWallet: true, address, verificationMethod: <did>#delegate-N }`. `btnSign` refuses to sign until it is delegated.
  - The wallet code lives in `did-ethr.js`: `connectEthrWallet`, `sendRegistryTx` (pre-checks owner and balance), `addEthrDelegate`/`revokeEthrDelegate`, and `waitForDelegate`, which polls the resolver until the delegate appears or disappears and returns its fragment. Delegate numbering is assigned by the resolver, so always read it back; never compute it.
  - The user performs on-chain transactions in their own Chrome; never confirm transactions for them. Avoid `changeOwner` on the user's DID (irreversible).
  - Without MetaMask, test with a fake `window.ethereum`: forward reads to Tenderly and reject `eth_sendTransaction` with code 4001 to inspect the encoded tx. For the post-receipt path, override the global `sendRegistryTx` and `ETHR.importResolver`.
  - Step 3 (JWT interop) is optional.
- `TODO.md` is the original exercise brief. Its example JSON is VC v1. The implementation deliberately uses v2.0 (`validFrom`/`validUntil`, `https://www.w3.org/ns/credentials/v2`).

## Commands

```bash
python -m http.server 8000
```

```bash
npm install
```

```bash
node test.js
```

- The first command serves the page. On this machine, port 8000 is sometimes taken by another service; `.claude/launch.json` uses 8765.
- `test.js` needs Node 20+ and network access. It fetches ethers from the exact CDN URL in `index.html`, checks it against the SRI hash, then loads `vc.js`, `did-key.js` and `did-ethr.js` into one `vm` context. These files have no DOM access, so no stubs are needed.
- `npm install` (once) is needed only because Node can't `import()` https URLs inside a `vm` context. The test swaps `ETHR.importResolver` for the npm copies and asserts their versions match `ETHR.resolverModules`, so keep `package.json` and those URLs in sync. The page itself needs no install.
- `stubResolver(docFor)` in `test.js` fakes on-chain state (e.g. delegate granted vs revoked). Give each stub a unique `rpcUrl`, because resolvers are cached per URL.
- The resolution tests also use real third-party Sepolia DIDs (with delegates, deactivated, owner moved). They're public chain data and could in theory change.
- The tests cover:
  - the W3C `vc-di-eddsa` B.3 vector (the official `proofValue` must be reproduced byte for byte);
  - JCS edge cases;
  - sign/verify/tamper checks for both suites;
  - did:ethr parsing rules;
  - `test-fixtures.json`, VCs signed by the pre-refactor hand-written implementation, which must keep verifying. Don't regenerate them; they guard format compatibility.
- There's no single-test runner. Comment out sections of `test.js` if you need to.
- If the Sepolia RPC is down, did:ethr tests still pass through the offline fallback.
- Opening `index.html` via `file://` works. The site is deployed to GitHub Pages from the root of `main` (https://chenyan1114.github.io/dpp/, `.nojekyll`), so pushing `main` deploys it.

## Architecture

All files are classic scripts (not ES modules, so double-clicking the file still works) that share one global scope. `index.html` loads them in this order: ethers CDN → `vc.js` → `did-key.js` → `did-ethr.js` → `ui.js`. The local four are injected by a small inline loader with `?t=<Date.now()>` and `async = false`. This is because GitHub Pages sends `Cache-Control: max-age=600`, and after a deploy browsers mixed cached old JS with new HTML, which broke the page. Add new local scripts to that loader list, not as plain `<script src>` tags.

- **`vc.js`**: the shared core. It holds base58btc, `concatBytes`, `sha256`, `jcs` (RFC 8785: sort keys and leave everything else to `JSON.stringify`), the `report()` helper, the generic Data Integrity flow (`createProof` / `verifyProof`), `buildVc`, and `verifyVc`. It defines two registries that the method files fill in:
  - `DID_METHODS[prefix] = { name, hint, generate(), parse(did), describe(info) }`
  - `SUITES[cryptosuite] = { sigLen, fragment(did), strictFragment, note, sign(keys, hashData), verify(r, ctx) }`
- **`did-key.js` / `did-ethr.js`**: each registers one DID method and one suite. `DID_METHODS` entries also have `resolve(did, { rpcUrl })`: did:key derives its doc locally, did:ethr goes through the resolver.
  - Key objects are `{ did, cryptosuite, privateKey | signingKey, verificationMethod? }`. `verificationMethod` overrides the default `<did>#<suite.fragment(did)>`, e.g. for a delegate key.
  - Fragment validation is each suite's job inside `verify(r, { hashData, sig, did, didInfo, fragment, rpcUrl })`.
  - `did-ethr.js` must not touch `ethers` at load time (only inside functions, via `requireEthers()`). That way did:key still works when the CDN fails.
- **`ui.js`**: DOM wiring only. The radio buttons' `value` is the `DID_METHODS` key. The `<pre id="vcOut">` text is the source of truth for the current VC: sign, verify, copy and download all re-parse it.

Adding a DID method or cryptosuite means registering it in both maps. `ui.js` dispatches through the maps, so it shouldn't need changes.

### Invariants (byte-exact interop depends on these)

- Proof options are built first. `hashData = SHA256(JCS(proofOptions)) || SHA256(JCS(unsecuredDoc))`, with the proof options hash **first**.
- `proofOptions` carries a copy of the document's `@context`. On verify, it must be a prefix of the document's `@context`, and the copy replaces the document's before hashing.
- `verificationMethod` is `<issuer DID>#<fragment>`, where the DID must equal `vc.issuer`. For did:key the fragment is the fingerprint (a mismatch is only a warning). For did:ethr it must name a key in the resolved DID document's `assertionMethod`.
- `proofValue` is `"z" + base58btc(signature)`. Only a single `proof` object is supported. Signing refuses a document that already has one.

### Verification reports

`report()` returns `{ fails, warns, passes, infos }` plus two helpers:
- `r.check(cond, passMsg, failMsg)`: a failure counts as an error.
- `r.soft(cond, passMsg, warnMsg)`: a failure is only a warning.

Only `fails` make verification fail. The rule: ✗ means the VC violates VC Data Model v2.0, or the signature or issuer can't be verified; ⚠ means it merely differs from this demo's expectations. Remember that `id`, `validFrom` and `validUntil` are optional in v2.0. Examples of ⚠:
- a non-`urn:uuid` id;
- missing ISO claims or `IsoCertificationCredential`;
- an unresolvable `credentialSubject.id`.
- mismatches against the current form or the in-page DIDs, so an uploaded external VC with a valid signature still passes;
- an unreachable RPC.

`ui.js` prefixes the proof results with `[簽名]`.

Signing requires `issuerKeys.did === vc.issuer`. If the user regenerates DIDs after building a VC, signing is refused on purpose (teaching point: a private key equals signing capability).

`DPP與VC實作說明.md` is the long-form design doc and cites file and function names (§6–§11, §17). Update it when you rename things.
