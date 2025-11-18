# Crate smashing

This is a temporary document for notes to share between us while
hacking on the `crate-smashing` branch.

### On branch management

So we don't tread on each others toes don't force push to the branch.
Since we are basically working on different crates we shouldn't get
too many conflicts.

## Currently working on

### @jamillambert

`address` move from `bitcoin` to `addressees`
- Needs the following to move first:
  - `network` -> new crate
  - `witness_program` and `witness_version` -> `primitives`?
  - `keys` -> `crypto`?
