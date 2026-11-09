//! An in-memory socket for driving connections without the network.
//!
//! Each half records what a test needs to see: where every read landed (to
//! check that received bodies were not copied out of it) and how many file
//! regions went through `send_file`.
#![allow(dead_code)]

use std::{
    borrow::Borrow,
    cell::{Cell, RefCell},
    fs::File,
    io,
    ops::Range,
    rc::Rc,
};

use async_channel::{Receiver, Sender};
use http_kit_io::{BufResult, IoBuf, IoBufMut, IoVectoredBuf, Read, SendFile, Write};

/// Greetings in Chinese, Japanese and Korean, for bodies and fields.
pub const CJK: &str = "你好，世界。こんにちは、世界。안녕하세요, 세계.";

/// The address ranges of the buffers reads were made into.
pub type ReadLog = Rc<RefCell<Vec<Range<usize>>>>;

/// The receiving end of a one-way pipe.
pub struct PipeReader {
    chunks: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    reads: ReadLog,
}

/// The sending end of a one-way pipe.
pub struct PipeWriter {
    chunks: Option<Sender<Vec<u8>>>,
    send_file_calls: Rc<Cell<usize>>,
}

/// A one-way pipe.
pub fn pipe() -> (PipeWriter, PipeReader) {
    let (tx, rx) = async_channel::unbounded();
    (
        PipeWriter {
            chunks: Some(tx),
            send_file_calls: Rc::default(),
        },
        PipeReader {
            chunks: rx,
            pending: Vec::new(),
            reads: Rc::default(),
        },
    )
}

/// The two ends of a connection: each is a read half and a write half.
pub struct Ends {
    pub server: (PipeReader, PipeWriter),
    pub client: (PipeReader, PipeWriter),
}

pub fn connection() -> Ends {
    let (to_server, server_in) = pipe();
    let (to_client, client_in) = pipe();
    Ends {
        server: (server_in, to_client),
        client: (client_in, to_server),
    }
}

impl PipeReader {
    /// Where this half's reads landed.
    pub fn reads(&self) -> ReadLog {
        self.reads.clone()
    }

    /// Reads whatever arrives next; empty at the end of the stream.
    pub async fn next_chunk(&mut self) -> Vec<u8> {
        if !self.pending.is_empty() {
            return std::mem::take(&mut self.pending);
        }
        self.chunks.recv().await.unwrap_or_default()
    }

    /// Whatever has arrived, without waiting.
    pub fn try_chunk(&mut self) -> Option<Vec<u8>> {
        if !self.pending.is_empty() {
            return Some(std::mem::take(&mut self.pending));
        }
        self.chunks.try_recv().ok()
    }

    /// Reads until the writer shuts down.
    pub async fn read_to_end(&mut self) -> Vec<u8> {
        let mut out = std::mem::take(&mut self.pending);
        while let Ok(chunk) = self.chunks.recv().await {
            out.extend(chunk);
        }
        out
    }

    /// Reads until `needle` has arrived, returning everything up to and
    /// including it and keeping the rest.
    pub async fn until(&mut self, needle: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            if let Some(at) = out.windows(needle.len()).position(|w| w == needle) {
                let rest = out.split_off(at + needle.len());
                self.pending.splice(0..0, rest);
                return out;
            }
            let chunk = self.next_chunk().await;
            assert!(
                !chunk.is_empty(),
                "stream ended before {:?}",
                String::from_utf8_lossy(needle)
            );
            out.extend(chunk);
        }
    }
}

impl PipeWriter {
    /// How many times `send_file` was called on this half.
    pub fn send_file_calls(&self) -> Rc<Cell<usize>> {
        self.send_file_calls.clone()
    }

    /// Sends raw bytes.
    pub fn send(&self, bytes: &[u8]) {
        self.chunks
            .as_ref()
            .expect("writer is open")
            .try_send(bytes.to_vec())
            .expect("reader is open");
    }

    /// Shuts down the write direction.
    pub fn close(&mut self) {
        self.chunks = None;
    }

    fn push(&self, bytes: Vec<u8>) -> io::Result<usize> {
        let len = bytes.len();
        match &self.chunks {
            Some(chunks) if chunks.try_send(bytes).is_ok() => Ok(len),
            _ => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

impl Read for PipeReader {
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        if self.pending.is_empty() {
            match self.chunks.recv().await {
                Ok(chunk) => self.pending = chunk,
                Err(_) => return BufResult(Ok(0), buf),
            }
        }
        let filled = buf.buf_len();
        let room = buf.as_uninit();
        let start = room.as_ptr().addr() + filled;
        let n = self.pending.len().min(room.len() - filled);
        self.reads.borrow_mut().push(start..start + n);
        buf.extend_from_slice(&self.pending[..n])
            .expect("the data fits the room the caller gave");
        self.pending.drain(..n);
        BufResult(Ok(n), buf)
    }
}

impl Write for PipeWriter {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let result = self.push(buf.as_init().to_vec());
        BufResult(result, buf)
    }

    async fn write_vectored<B: IoVectoredBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let bytes = buf.iter_slice().flatten().copied().collect();
        let result = self.push(bytes);
        BufResult(result, buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.close();
        Ok(())
    }
}

impl SendFile for PipeWriter {
    async fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> BufResult<usize, F> {
        self.send_file_calls.set(self.send_file_calls.get() + 1);
        let mut region = vec![0; len];
        #[cfg(unix)]
        let read = std::os::unix::fs::FileExt::read_at(file.borrow(), &mut region, offset);
        #[cfg(windows)]
        let read = std::os::windows::fs::FileExt::seek_read(file.borrow(), &mut region, offset);
        let result = read.and_then(|n| {
            region.truncate(n);
            self.push(region)
        });
        BufResult(result, file)
    }
}

/// Whether every byte of `data` lies inside memory that reads wrote into,
/// so it was handed up without being copied.
pub fn within_reads(data: &[u8], reads: &ReadLog) -> bool {
    let start = data.as_ptr().addr();
    let wanted = start..start + data.len();
    // Consecutive reads into one buffer are adjacent; merge them.
    let mut ranges = RefCell::borrow(reads).clone();
    ranges.sort_by_key(|range| range.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged
        .iter()
        .any(|read| read.start <= wanted.start && wanted.end <= read.end)
}
