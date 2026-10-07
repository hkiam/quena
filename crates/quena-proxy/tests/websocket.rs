//! WebSocket frame recording: pump forwards raw bytes and logs unmasked frames.

use quena_proxy::wsframe::{pump, record, DIR_CLIENT, DIR_SERVER, FrameLog, FrameReader};
use tokio::io::duplex;

fn text_frame(payload: &[u8], masked: bool) -> Vec<u8> {
    let mut f = vec![0x81];
    if masked {
        f.push(0x80 | payload.len() as u8);
        let key = [0x11, 0x22, 0x33, 0x44];
        f.extend_from_slice(&key);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i & 3]));
    } else {
        f.push(payload.len() as u8);
        f.extend_from_slice(payload);
    }
    f
}

#[tokio::test]
async fn pump_forwards_and_logs() {
    // src carries two client frames; verify dst receives raw bytes and the log has unmasked payloads.
    let mut input = text_frame(b"hello", true);
    input.extend(text_frame(b"world", true));
    let (mut src_w, src_r) = duplex(4096);
    let (dst_w, mut dst_r) = duplex(4096);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    src_w.write_all(&input).await.unwrap();
    drop(src_w); // EOF
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    let queued = std::sync::atomic::AtomicUsize::new(0);
    let last = std::sync::atomic::AtomicI64::new(0);
    let log = FrameLog { tx: &tx, queued: &queued, budget: 1 << 20, last: &last };
    let (total, err) = pump(src_r, dst_w, DIR_CLIENT, &log).await;
    drop(tx);
    assert_eq!(total, input.len() as u64);
    assert_eq!(err, None);
    let mut forwarded = Vec::new();
    dst_r.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(forwarded, input, "raw bytes forwarded unchanged");
    let mut logs = Vec::new();
    while let Some(r) = rx.recv().await {
        logs.push(r);
    }
    assert_eq!(logs.len(), 2);
    // record: dir(1) opcode(1) fin(1) rsv(1) ts(8) len(4) payload
    assert_eq!(logs[0][0], DIR_CLIENT);
    assert_eq!(logs[0][1], 0x1);
    assert_eq!(&logs[0][16..], b"hello");
    assert_eq!(&logs[1][16..], b"world");
}

#[test]
fn record_roundtrip() {
    use quena_model::wslog::Frame;
    let f = Frame { fin: true, rsv: 0, opcode: 0x2, payload: vec![1, 2, 3] };
    let r = record(DIR_SERVER, &f, 12345);
    assert_eq!(r[0], DIR_SERVER);
    assert_eq!(r[1], 0x2);
    assert_eq!(i64::from_le_bytes(r[4..12].try_into().unwrap()), 12345);
    assert_eq!(u32::from_le_bytes(r[12..16].try_into().unwrap()), 3);
    assert_eq!(&r[16..], &[1, 2, 3]);
}

#[tokio::test]
async fn reader_handles_split_reads() {
    // Deliver a frame in tiny chunks; the reader must reassemble it.
    let frame = text_frame(&vec![b'z'; 100], false);
    let (mut w, r) = duplex(8);
    use tokio::io::AsyncWriteExt;
    let f2 = frame.clone();
    tokio::spawn(async move {
        for b in f2 {
            let _ = w.write_all(&[b]).await;
        }
    });
    let mut reader = FrameReader::default();
    let mut src = r;
    let got = reader.next(&mut src).await.unwrap().unwrap();
    assert_eq!(got.frame.payload.len(), 100);
    assert_eq!(got.frame.opcode, 1);
}
