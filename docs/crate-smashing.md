# Crate smashing

This is a temporary document for notes to share between us while
hacking on the `crate-smashing` branch.

### On branch management

So we don't tread on each others toes don't force push to the branch.
Since we are basically working on different crates we shouldn't get
too many conflicts.

## Currently working on

### @jamillambert

`address` move from `bitcoin` to `addresses`
- Needs the following first:
  - Move `keys` -> `crypto` (tcharding doing)
  - Move `params` to `network`
  - Create extension trait for `AddressScript` including dealing with the script extension traits
- Recently done in `address`
  - Import from new crates instead of bitcoin where possible
  - Moved `NetworkKind` to `network`
- Unfinished and un pushed work:
  - `AddressScriptExt`
  - Moving `params` to `network`
