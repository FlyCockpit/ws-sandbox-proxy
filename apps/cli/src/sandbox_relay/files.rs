//! A stop-and-wait file window. Byte identity ACKs cannot mint credits.
use super::output::{Frame, ResendTimer};
use sandbox_protocol::{StreamBinaryMetadata, StreamChunkFlags, StreamKind};
use sandbox_runtime::{FILE_CHUNK_BYTES, FileContent};
use std::time::Instant;
pub struct DownloadWindow {
    content: FileContent,
    sequence: u64,
    offset: u64,
    pending: Option<Frame>,
    sent: Option<Instant>,
    resend: ResendTimer,
    ended: bool,
    started: Instant,
    progressed: Instant,
}
impl DownloadWindow {
    pub fn new(content: FileContent) -> Self {
        let now = Instant::now();
        Self {
            content,
            sequence: 0,
            offset: 0,
            pending: None,
            sent: None,
            resend: ResendTimer::default(),
            ended: false,
            started: now,
            progressed: now,
        }
    }
    pub fn started(&self) -> Instant {
        self.started
    }
    /// Last exact ACK (or creation). A late or wrong ACK never refreshes it.
    pub fn progressed(&self) -> Instant {
        self.progressed
    }
    #[cfg(test)]
    pub fn backdate(&mut self, by: std::time::Duration) {
        self.started -= by;
        self.progressed -= by;
    }
    pub fn ack(&mut self, sequence: u64, offset: u64) {
        if let Some(frame) = &self.pending
            && frame.metadata.sequence == sequence
            && self.offset + frame.body_len() as u64 == offset
        {
            self.offset = offset;
            self.sequence += 1;
            self.ended = frame.metadata.final_chunk == Some(true);
            self.pending = None;
            self.resend.progressed();
            self.progressed = Instant::now();
        }
    }
    pub fn drained(&self) -> bool {
        self.ended
    }
    pub fn poll(
        &mut self,
        operation: &str,
        generation: u64,
        attempt: u64,
        now: Instant,
    ) -> anyhow::Result<Option<Frame>> {
        if self.ended {
            return Ok(None);
        }
        if let Some(frame) = &self.pending {
            if self.sent.is_some_and(|sent| !self.resend.due(sent, now)) {
                return Ok(None);
            }
            self.sent = Some(now);
            self.resend.resent();
            return Ok(Some(frame.clone()));
        }
        let bytes = self.content.read_chunk(self.offset, FILE_CHUNK_BYTES)?;
        let ended = self.offset + bytes.len() as u64 == self.content.len() as u64;
        let frame = Frame::encode(
            StreamBinaryMetadata {
                r#type: if ended {
                    StreamKind::End
                } else {
                    StreamKind::Chunk
                },
                stream_id: format!("file-{operation}"),
                operation_id: operation.into(),
                generation,
                attempt,
                sequence: self.sequence,
                offset: Some(self.offset),
                gap_start: None,
                flags: Some(StreamChunkFlags {
                    file_download: Some(true),
                    file_upload: None,
                    stdin: None,
                    stdout: None,
                    stderr: None,
                }),
                final_chunk: Some(ended),
            },
            &bytes,
        )?;
        self.pending = Some(frame.clone());
        self.sent = Some(now);
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn slow_consumer_duplicate_and_wrong_acks_keep_one_chunk_in_flight() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let content = FileContent::from_bytes(&vec![255; FILE_CHUNK_BYTES * 3 + 1]).unwrap();
        let mut window = DownloadWindow::new(content);
        let now = Instant::now();
        let first = window.poll("op", 2, 3, now).unwrap().unwrap();
        assert_eq!(first.body_len(), FILE_CHUNK_BYTES);
        for _ in 0..1000 {
            window.ack(9, 9);
            window.ack(99, FILE_CHUNK_BYTES as u64);
            window.ack(0, 7);
            assert!(window.poll("op", 2, 3, now).unwrap().is_none());
        }
        let replay = window
            .poll("op", 2, 3, now + Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(replay.metadata, first.metadata);
        assert_eq!(replay.encoded(), first.encoded());
        assert_eq!(
            &first.encoded()[..],
            &sandbox_protocol::encode_binary_frame(&first.metadata, first.body()).unwrap()[..]
        );
        assert_eq!(first.body(), &vec![255; FILE_CHUNK_BYTES][..]);
        window.ack(0, FILE_CHUNK_BYTES as u64);
        window.ack(0, FILE_CHUNK_BYTES as u64);
        for seq in 1..=3 {
            let frame = window.poll("op", 2, 3, now).unwrap().unwrap();
            assert_eq!(frame.metadata.sequence, seq);
            window.ack(
                seq,
                frame.metadata.offset.unwrap() + frame.body_len() as u64,
            );
        }
        assert!(window.drained());
    }
    #[test]
    fn empty_file_requires_ack_of_the_final_marker() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let mut window = DownloadWindow::new(FileContent::from_bytes(&[]).unwrap());
        assert!(!window.drained());
        let frame = window.poll("empty", 1, 1, Instant::now()).unwrap().unwrap();
        assert!(frame.body().is_empty());
        assert_eq!(frame.metadata.final_chunk, Some(true));
        window.ack(0, 0);
        assert!(window.drained());
    }
    /// D3a: a stalled chunk is resent after 250 ms, 500 ms, 1 s, then every
    /// 2 s; its exact ACK restores the 250 ms interval for the next chunk.
    #[test]
    fn resend_backs_off_until_the_exact_ack() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let content = FileContent::from_bytes(&vec![7; FILE_CHUNK_BYTES + 1]).unwrap();
        let mut window = DownloadWindow::new(content);
        let ms = Duration::from_millis;
        let t0 = Instant::now();
        let first = window.poll("op", 1, 1, t0).unwrap().unwrap();
        let mut last = t0;
        for gap in [250, 500, 1000, 2000, 2000] {
            assert!(
                window
                    .poll("op", 1, 1, last + ms(gap - 1))
                    .unwrap()
                    .is_none()
            );
            last += ms(gap);
            let again = window.poll("op", 1, 1, last).unwrap().unwrap();
            assert_eq!(again.encoded(), first.encoded());
        }
        window.ack(0, FILE_CHUNK_BYTES as u64);
        let next = window.poll("op", 1, 1, last).unwrap().unwrap();
        assert_eq!(next.metadata.sequence, 1);
        assert!(window.poll("op", 1, 1, last + ms(249)).unwrap().is_none());
        assert!(window.poll("op", 1, 1, last + ms(250)).unwrap().is_some());
    }
}
