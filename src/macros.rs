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

#![macro_escape]

#[macro_export]
macro_rules! nu_select(
  ($($name:pat from $rx:expr => $code:expr),+) => ({
    nu_select!{ $($name from $rx using recv => $code),+ }
  });
  ($($name:pat from $rx:expr using $meth:ident => $code:expr),+) => ({
    use rustrt::local::Local;
    use rustrt::task::Task;
    use sync::comm::Packet;

    let task: Box<Task> = Local::take();

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
      let packets = [ $( &$rx as &Packet, )+ ];
      task.deschedule(packets.len(), |task| {
        match packets[started_count].start_selection(task) {
          Ok(()) => {
            started_count += 1;
            Ok(())
          }
          Err(task) => Err(task)
        }
      });

      let mut i = -1;
      $(
        // Abort every one, but only react to the first
        if { i += 1; i < started_count } &&
           // If start_selection() failed, abort_selection() will fail too,
           // but it still counts as "data available". FIXME: should we swap
           // the following two conditions so that packets[started_count - 1].
           // abort_selection() is never called?
           (packets[i].abort_selection() || i == started_count - 1) {
          // Abort the remainder, ignoring their return values
          i += 1;
          while i < started_count {
            packets[i].abort_selection();
            i += 1;
          }
          // React to the first
          let $name = $rx.$meth();
          $code
        }
      )else+
    else { 
      println!("i = {} , started_count {}", i, started_count);
      fail!("we didn't find the ready receiver, but we should have had one"); }
    }
  })
)


