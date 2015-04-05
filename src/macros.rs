// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Macros
//!
//! Macros available to users of the Bitcoin library

#[macro_export]
macro_rules! nu_select {
  ($($name:pat = $rx:expr => $code:expr),+) => ({
    nu_select!{ $($name = $rx, recv => $code),+ }
  });
  ($($name:pat = $rx:expr, $meth:ident => $code:expr),+) => ({
    use rustrt::local::Local;
    use rustrt::task::Task;
    use sync::comm::Packet;

    // Is anything already ready to receive? Grab it without waiting.
    $(
      if (&$rx as &Packet).can_recv() {
        let $name = $rx.$meth();
        $code
      }
    )else+
    else {

      // Start selecting on as many as we need to before getting a bite.
      // Keep count of how many, since we need to abort every selection
      // that we started.
      let mut started_count = 0;
      // Restrict lifetime of borrows in `packets`
      {
        let packets = [ $( &$rx as &Packet, )+ ];

        let task: Box<Task> = Local::take();
        task.deschedule(packets.len(), |task| {
          match packets[started_count].start_selection(task) {
            Ok(()) => {
              started_count += 1;
              Ok(())
            }
            Err(task) => Err(task)
          }
        });
      }

      let mut i = 0;
      let ret = $(
        // Abort the receivers, stopping at the first ready one to get its data.
        if { i += 1; i <= started_count } &&
           // If start_selection() failed, abort_selection() will fail too,
           // but it still counts as "data available".
           ($rx.abort_selection() || i == started_count) {
          // React to the first
          let $name = $rx.$meth();
          $code
        })else+
        else {
          fail!("we didn't find the ready receiver, but we should have had one");
        };
      // At this point, the first i receivers have been aborted. We need to abort the rest:
      $(if i > 0 {
        i -= 1;
      } else {
        $rx.abort_selection();
      })+
      let _ = i; // Shut up `i -= 1 but i is never read` warning
      // Return
      ret
    }
  })
}

#[macro_export]
macro_rules! user_enum {
  ($(#[$attr:meta])* pub enum $name:ident { $(#[$doc:meta] $elem:ident <-> $txt:expr),* }) => (
    $(#[$attr])*
    pub enum $name {
      $(#[$doc] $elem),*
    }

    impl ::std::fmt::Debug for $name {
      fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        f.pad(match *self {
          $($elem => $txt),*
        })
      }
    }

    impl<S: ::serialize::Encoder<E>, E> ::serialize::Encodable<S, E> for $name {
      fn encode(&self, s: &mut S) -> Result<(), E> {
        s.emit_str(self.to_string().as_slice())
      }
    }

    impl <D: ::serialize::Decoder<E>, E> ::serialize::Decodable<D, E> for $name {
      fn decode(d: &mut D) -> Result<$name, E> {
        let s = try!(d.read_str());
        $( if s.as_slice() == $txt { Ok($name::$elem) } )else*
        else { Err(d.error(format!("unknown `{}`", s).as_slice())) }
      }
    }
  );
}

