// D3b: command-output frames follow the chunk size the current connection's
// `hello.ok` negotiated (FakeRuntime echoes its argv as stdout).
mod output_chunk {
    use super::*;

    #[test]
    fn d3b_output_frames_follow_the_negotiated_chunk_size() {
        // The current answer is bounded by the daemon's own offer.
        for (answer, chunk) in [
            (Some(8192_u32), 8192_usize),
            (Some(16_384_u32), 16_384),
            (Some(65_536), 65_536),
            (Some(1_048_576), 65_536),
        ] {
            let (_dir, binding, journal, _fake, authority, relay) = relay_fixture();
            authority.attach(1);
            relay.set_output_chunk_bytes(answer);
            assert_eq!(relay.output_chunk_bytes(), chunk);
            let mut d = dispatch("cmd", "command.run", 1);
            let mut argv = vec!["true".to_string()];
            argv.extend((0..50).map(|i| format!("{i:03}{}", "x".repeat(497))));
            d.argv = Some(argv);
            admit(&relay, &journal, &binding, &authority, d);
            // Every byte is retained before the first poll, so frame sizes are
            // decided by the negotiated size alone.
            let deadline = Instant::now() + Duration::from_secs(5);
            while journal.lookup("cmd").unwrap().phase
                != crate::sandbox_relay::journal::ReceiptPhase::Result
            {
                assert!(Instant::now() < deadline, "command never finished");
                thread::sleep(Duration::from_millis(2));
            }
            let (finished, frames) = done_with_output(&relay, "cmd");
            assert_eq!(finished.state, OperationState::Succeeded);
            let total: usize = frames.iter().map(Frame::body_len).sum();
            assert!(total > 16_384, "{total}");
            assert_eq!(frames.len(), total.div_ceil(chunk), "{answer:?}");
            let (last, full) = frames.split_last().unwrap();
            assert!(full.iter().all(|f| f.body_len() == chunk), "{answer:?}");
            assert!(last.body_len() <= chunk);
            let mut offset = 0;
            for (sequence, frame) in frames.iter().enumerate() {
                assert_eq!(frame.metadata.sequence, sequence as u64);
                assert_eq!(frame.metadata.offset, Some(offset));
                offset += frame.body_len() as u64;
            }
        }
    }
}
