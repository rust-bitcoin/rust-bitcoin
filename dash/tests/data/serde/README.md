Serialization input/output
==========================

Files here contain hex strings and binary data representing types used for
regression testing.

- *_hex: consensus encoded types represented as hex strings
- *_ser: consensus encoded types represented as binary data
- *_bincode: types serialized with serde as bincode

We consensus deserialize, serde serialize, then check against the expected data
to verify no serde regressions have been introduced.
