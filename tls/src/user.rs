//! TLS in user space: rustls encrypts and decrypts, the socket carries
//! ciphertext.
//!
//! The halves share one [`Engine`], borrowed only between awaits. A read
//! lands in the reading half's own buffer, so the writing half can encrypt
//! while it is in flight; a write sends records the reading half produced
//! (a key update's answer) ahead of its own.

use std::{borrow::Borrow, cell::RefCell, fs::File, io, mem, rc::Rc};

use http_kit_io::{BufResult, IntoInner as _, IoBuf, IoBufMut, IoVectoredBuf, Read, Write};

use crate::{
    engine::{Engine, READ_SIZE, Records},
    side::Side,
};

/// The most plaintext one write encrypts: four full records.
const MAX_WRITE: usize = 4 << 14;

/// Slices of a vectored write shorter than this are gathered into one record
/// rather than each sealed alone, where framing would cost more than the copy.
const GATHER_BELOW: usize = 1024;

/// The reading half.
pub(crate) struct Reader<R, D: Side> {
    io: R,
    engine: Rc<RefCell<Engine<D>>>,
    /// Where socket reads land: a copy of the unprocessed tail of
    /// [`Engine::incoming`], then the new bytes.
    landing: Vec<u8>,
}

/// The writing half.
pub(crate) struct Writer<W, D: Side> {
    io: W,
    engine: Rc<RefCell<Engine<D>>>,
    out: Records,
    /// Small slices of a vectored write, gathered into one record.
    gather: Vec<u8>,
    /// A file region read for encryption.
    region: Vec<u8>,
}

pub(crate) fn split<R, W, D: Side>(engine: Engine<D>, io: (R, W)) -> (Reader<R, D>, Writer<W, D>) {
    let engine = Rc::new(RefCell::new(engine));
    (
        Reader {
            io: io.0,
            engine: engine.clone(),
            landing: Vec::new(),
        },
        Writer {
            io: io.1,
            engine,
            out: Records::default(),
            gather: Vec::new(),
            region: Vec::new(),
        },
    )
}

fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "the peer closed the connection without a TLS close_notify",
    )
}

impl<R, D: Side> Reader<R, D> {
    pub(crate) const fn get_ref(&self) -> &R {
        &self.io
    }
}

impl<W, D: Side> Writer<W, D> {
    pub(crate) const fn get_ref(&self) -> &W {
        &self.io
    }
}

impl<R: Read, D: Side> Reader<R, D> {
    pub(crate) async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        if buf.as_uninit().is_empty() {
            return BufResult(Ok(0), buf);
        }
        loop {
            let held = {
                let mut engine = self.engine.borrow_mut();
                match engine.read_into(buf.as_uninit()) {
                    Ok(0) if engine.peer_closed => return set_read(buf, Ok(0)),
                    Ok(0) => {}
                    res => return set_read(buf, res),
                }
                self.landing.clear();
                self.landing.extend_from_slice(&engine.incoming);
                engine.incoming.len()
            };
            self.landing.reserve(READ_SIZE);
            let landing = mem::take(&mut self.landing);
            let BufResult(res, slice) = self.io.read(landing.slice(held..)).await;
            self.landing = slice.into_inner();
            match res {
                Ok(0) => return set_read(buf, Err(truncated())),
                Ok(_) => {
                    let mut engine = self.engine.borrow_mut();
                    // The writing half may have had rustls discard part of
                    // the tail meanwhile; the landed copy loses the same.
                    let discarded = held - engine.incoming.len();
                    self.landing.drain(..discarded);
                    mem::swap(&mut engine.incoming, &mut self.landing);
                }
                Err(error) => return set_read(buf, Err(error)),
            }
        }
    }
}

/// Finishes a read into `buf`: its length is what was read.
fn set_read<B: IoBufMut>(mut buf: B, res: io::Result<usize>) -> BufResult<usize, B> {
    let len = *res.as_ref().unwrap_or(&0);
    // SAFETY: `Engine::read_into` initialized the first `len` bytes.
    unsafe { buf.set_len(len) };
    BufResult(res, buf)
}

impl<W: Write, D: Side> Writer<W, D> {
    /// Sends what the reading half owes the peer and what `seal` encrypts,
    /// in that order.
    async fn seal(
        &mut self,
        seal: impl FnOnce(&mut Engine<D>, &mut Records) -> io::Result<()>,
    ) -> io::Result<()> {
        {
            let mut engine = self.engine.borrow_mut();
            self.out.take_from(&mut engine.owed);
            seal(&mut engine, &mut self.out)?;
        }
        self.out.send(&mut self.io).await
    }

    pub(crate) async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let n = buf.buf_len().min(MAX_WRITE);
        let res = self
            .seal(|engine, out| engine.encrypt(&buf.as_init()[..n], out))
            .await;
        BufResult(res.map(|()| n), buf)
    }

    pub(crate) async fn write_vectored<B: IoVectoredBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let mut gather = mem::take(&mut self.gather);
        let mut taken = 0;
        let res = self
            .seal(|engine, out| {
                for slice in buf.iter_slice() {
                    let slice = &slice[..slice.len().min(MAX_WRITE - taken)];
                    if slice.len() < GATHER_BELOW {
                        gather.extend_from_slice(slice);
                    } else {
                        engine.encrypt(&gather, out)?;
                        gather.clear();
                        engine.encrypt(slice, out)?;
                    }
                    taken += slice.len();
                    if taken == MAX_WRITE {
                        break;
                    }
                }
                engine.encrypt(&gather, out)
            })
            .await;
        gather.clear();
        self.gather = gather;
        BufResult(res.map(|()| taken), buf)
    }

    pub(crate) async fn flush(&mut self) -> io::Result<()> {
        self.seal(|_, _| Ok(())).await?;
        self.io.flush().await
    }

    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        self.seal(Engine::close_notify).await?;
        self.io.shutdown().await
    }

    /// Reads up to a write's worth of the region and encrypts it: there is
    /// no file-to-socket path through user-space encryption.
    pub(crate) async fn send_file<F: Borrow<File>>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> BufResult<usize, F> {
        let mut region = mem::take(&mut self.region);
        region.resize(len.min(MAX_WRITE), 0);
        let read = read_at(file.borrow(), &mut region, offset);
        let res = match read {
            Ok(n) => self
                .seal(|engine, out| engine.encrypt(&region[..n], out))
                .await
                .map(|()| n),
            Err(error) => Err(error),
        };
        self.region = region;
        BufResult(res, file)
    }
}

/// One positional read, as `pread(2)`: the file's own position is not used.
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_read(file, buf, offset)
    }
}
