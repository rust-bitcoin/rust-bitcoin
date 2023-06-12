// Rust Dash Library
// Written for Dash in 2022 by
//     The Dash Core Developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Dash Credit Withdrawal Special Transaction Components.
//!
//! The credit withdrawal special transaction is used to withdraw from the asset lock credit pool.
//!
//!
//! It is defined in DIPX [dip-000X.md](https://github.com/dashpay/dips/blob/master/dip-000X.md) as follows:
//!
//!
//! The special transaction type used for CrWithTx Transactions is 9.

pub mod unqualified_asset_unlock;
pub mod qualified_asset_unlock;
pub mod request_info;
