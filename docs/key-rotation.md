# Key rotation

Rotation is done *in band*: the new public key reaches clients inside an app
release that the **old** key signed. Clients never learn a key from the
network, so there is no trust-on-first-use window.

## Routine rotation (old key still safe)

1. **Generate** the new key on the release machine:
   `updsign keygen -out new.key` (prints the new public key, `NEWPUB`).
2. **Release N** (carries the new key):
   - Build the app with `publicKeys: [OLDPUB, NEWPUB]`.
   - Sign it with the **old** key and publish as usual
     (`updsign manifest add -key old.key ...`).
3. **Wait** until enough installs have moved to N. You decide the threshold;
   clients that skip N can still reach it as long as N stays in the manifest.
4. **Release N+1** (first one signed by the new key):
   - Build with `publicKeys: [NEWPUB]` (optionally keep `OLDPUB` for one more
     cycle).
   - Sign with `new.key`, add to the **same** manifest alongside N.
   - Keep N (old-signed) in the manifest: clients still on N-1 skip the entry
     they cannot verify (N+1) and update to N first, then to N+1.
5. **Retire** `old.key` (secure delete / HSM destroy) once the old-signed entry
   is no longer needed; remove N from the manifest when you are ready to cut
   off clients older than N.

Note: rollback protection means N+1 must have a higher version/build than N.

## Standby key (recommended from day one)

Ship a second, never-used public key (`STANDBY`) in every release:
`publicKeys: [ACTIVE, STANDBY]`. Keep the standby private key offline in a
different place. If the active key is lost, sign the next release with the
standby key and nothing is stranded. Rotate to a fresh standby afterwards.

## If the old key is compromised

Rotation through the old key is no longer trustworthy: the attacker can sign
too. Realistically you must distribute a fresh installer by another channel
(website, package repositories, store). Move quickly; during the window an
attacker holding the key and the server can push malicious updates. This is the
price of having no revocation channel; see the threat model.

## Checklist

- [ ] New key generated on the release machine, file mode 0600, backed up
      encrypted in two places.
- [ ] Release N tested: app accepts N signed by old key and contains `NEWPUB`.
- [ ] Release N+1 verified with `updsign verify -pub NEWPUB -manifest ...`.
- [ ] Manifest still lists N signed by the old key.
- [ ] Old key retired only after the cut-off decision.
