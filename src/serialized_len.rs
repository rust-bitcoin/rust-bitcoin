use crate::io;

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub(crate) struct WriteCounterThreshold {
    counter: usize,
    threshold: usize,
}

impl WriteCounterThreshold {
    pub(crate) fn new(threshold: usize) -> Self { Self { counter: 0, threshold } }
    pub(crate) fn bytes_written(&self) -> usize { self.counter }

    fn increment_counter(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.counter += buf.len();
        if self.counter > self.threshold {
            Err(io::Error::from(io::ErrorKind::Other))
        } else {
            Ok(buf.len())
        }
    }
}

impl io::Write for WriteCounterThreshold {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.increment_counter(buf) }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.increment_counter(buf)?;
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
