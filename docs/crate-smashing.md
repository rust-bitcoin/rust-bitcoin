# Crate smashing

This is a temporary document for notes to share between us while
hacking on the `crate-smashing` branch.

## On branch management

So we don't tread on each others toes don't force push to the branch.
Since we are basically working on different crates we shouldn't get
too many conflicts.

## Currently working on

### @jamillambert

`address` move from `bitcoin` to `addresses`

- Recently done in `address`
  - Import from new crates instead of bitcoin where possible
  - Moved `NetworkKind` to `network`
  - Create `AddressScriptExt`
  - Move address.rs and error.rs from bitcoin::address to addresses::address. Code move only to make it easier to see the changes.
  - Remove the address bits from bitcoin and addresses that should only be in the other.
  - Fix both bitcoin::address and addresses::address after the move so that everything works
- Unfinished work:
  - Docs
