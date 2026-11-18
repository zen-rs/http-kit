//! RFC 7541 Appendix C vectors, error/security boundary tests, CJK round-trips,
//! and the full `http2jp/hpack-test-case` wire conformance suite.

use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    process::Command,
};

use bytes::{Bytes, BytesMut};
use flate2::read::GzDecoder;
use http_kit_h2::hpack::{DecodeOutcome, Decoder, EncodeField, Encoder, HpackError};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tar::Archive;

const HPACK_TEST_CASE_URL: &str = "https://github.com/http2jp/hpack-test-case/archive/8a1406e7d14bfcb6c046021f13cc15cfb162726d.tar.gz";
const HPACK_TEST_CASE_SHA256: &str =
    "53355bf708fb890a235b3a679061d116a020818e92caaadbc243f9c91c4c48eb";

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex byte {b:#04x}"),
    }
}

fn unhex(hex: &str) -> Bytes {
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut iter = hex.bytes().filter(|b| !b.is_ascii_whitespace());
    while let Some(hi) = iter.next() {
        let lo = iter.next().expect("even number of hex digits");
        out.push((hex_nibble(hi) << 4) | hex_nibble(lo));
    }
    Bytes::from(out)
}

fn decode_pairs(decoder: &mut Decoder, hex_wire: &str) -> Vec<(String, String)> {
    let raw = unhex(hex_wire);
    let DecodeOutcome::Fields(fields) = decoder.decode(&raw, 64 * 1024).unwrap() else {
        panic!("unexpected TooLarge");
    };
    fields
        .into_iter()
        .map(|f| {
            (
                String::from_utf8(f.name.to_vec()).unwrap(),
                String::from_utf8(f.value.to_vec()).unwrap(),
            )
        })
        .collect()
}

fn pairs(slice: &[(&str, &str)]) -> Vec<(String, String)> {
    slice
        .iter()
        .map(|&(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

#[test]
fn rfc7541_appendix_c2_field_representations() {
    // C.2.1 Literal Header Field with Indexing
    let mut dec = Decoder::new(4096);
    assert_eq!(
        decode_pairs(
            &mut dec,
            "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"
        ),
        pairs(&[("custom-key", "custom-header")])
    );
    assert_eq!(dec.dynamic_table_size(), 55);

    // C.2.2 Literal Header Field without Indexing
    let mut dec = Decoder::new(4096);
    assert_eq!(
        decode_pairs(&mut dec, "040c 2f73 616d 706c 652f 7061 7468"),
        pairs(&[(":path", "/sample/path")])
    );
    assert_eq!(dec.dynamic_table_size(), 0);

    // C.2.3 Literal Header Field Never Indexed
    let mut dec = Decoder::new(4096);
    let raw = unhex("1008 7061 7373 776f 7264 0673 6563 7265 74");
    let DecodeOutcome::Fields(fields) = dec.decode(&raw, 64 * 1024).unwrap() else {
        panic!("unexpected TooLarge");
    };
    assert_eq!(fields.len(), 1);
    assert_eq!(&fields[0].name[..], b"password");
    assert_eq!(&fields[0].value[..], b"secret");
    assert!(fields[0].sensitive);
    assert_eq!(dec.dynamic_table_size(), 0);

    // C.2.4 Indexed Header Field
    let mut dec = Decoder::new(4096);
    assert_eq!(decode_pairs(&mut dec, "82"), pairs(&[(":method", "GET")]));
    assert_eq!(dec.dynamic_table_size(), 0);
}

#[test]
fn rfc7541_appendix_c3_and_c4_requests_without_and_with_huffman() {
    for (w1, w2, w3) in [
        // C.3: Requests without Huffman
        (
            "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
            "8286 84be 5808 6e6f 2d63 6163 6865",
            "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
        ),
        // C.4: Requests with Huffman
        (
            "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
            "8286 84be 5886 a8eb 1064 9cbf",
            "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
        ),
    ] {
        let mut dec = Decoder::new(4096);

        assert_eq!(
            decode_pairs(&mut dec, w1),
            pairs(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ])
        );
        assert_eq!(dec.dynamic_table_size(), 57);

        assert_eq!(
            decode_pairs(&mut dec, w2),
            pairs(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ])
        );
        assert_eq!(dec.dynamic_table_size(), 110);

        assert_eq!(
            decode_pairs(&mut dec, w3),
            pairs(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ])
        );
        assert_eq!(dec.dynamic_table_size(), 164);
    }
}

#[test]
fn rfc7541_appendix_c5_and_c6_responses_with_eviction() {
    for (w1, w2, w3) in [
        // C.5: Responses without Huffman (`max_table_size = 256`)
        (
            "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
            "4803 3330 37c1 c0bf",
            "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d 54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049 5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e 3d31",
        ),
        // C.6: Responses with Huffman (`max_table_size = 256`)
        (
            "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
            "4883 640e ffc1 c0bf",
            "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07",
        ),
    ] {
        let mut dec = Decoder::new(256);

        assert_eq!(
            decode_pairs(&mut dec, w1),
            pairs(&[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ])
        );
        assert_eq!(dec.dynamic_table_size(), 222);

        assert_eq!(
            decode_pairs(&mut dec, w2),
            pairs(&[
                (":status", "307"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ])
        );
        assert_eq!(dec.dynamic_table_size(), 222);

        assert_eq!(
            decode_pairs(&mut dec, w3),
            pairs(&[
                (":status", "200"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                ("location", "https://www.example.com"),
                ("content-encoding", "gzip"),
                (
                    "set-cookie",
                    "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
                ),
            ])
        );
        assert_eq!(dec.dynamic_table_size(), 215);
    }
}

#[test]
fn cjk_dynamic_table_caching_and_header_list_limit_sync() {
    let mut enc = Encoder::new(4096);
    let mut dec = Decoder::new(4096);

    let cjk_value = "中文测试 / 日本語テスト / 한국어 테스트";
    let mut buf = BytesMut::new();
    enc.encode(
        [
            EncodeField::new(b":method", b"GET"),
            EncodeField::new(b"x-cjk-greeting", cjk_value.as_bytes()),
            EncodeField::sensitive(b"x-secret-token", b"top-secret"),
        ],
        &mut buf,
    );

    let DecodeOutcome::Fields(first) = dec.decode(&buf.split().freeze(), 4096).unwrap() else {
        panic!("expected Fields");
    };
    assert_eq!(first.len(), 3);
    assert_eq!(
        first[1].parsed_name.as_ref().map(|n| n.as_str()),
        Some("x-cjk-greeting")
    );
    assert_eq!(
        first[1].parsed_value.as_ref().map(|v| v.as_bytes()),
        Some(cjk_value.as_bytes())
    );
    assert!(first[2].sensitive);

    // Second block hits the dynamic table for `x-cjk-greeting` (`1`-byte index)
    // and tests `TooLarge` synchronization!
    enc.encode(
        [
            EncodeField::new(b"x-cjk-greeting", cjk_value.as_bytes()),
            EncodeField::new(b"x-new-indexed", b"persists-across-too-large"),
            EncodeField::new(b"x-overflow-padding", &[b'z'; 512]),
        ],
        &mut buf,
    );
    let outcome = dec.decode(&buf.split().freeze(), 200).unwrap();
    assert_eq!(outcome, DecodeOutcome::TooLarge { limit: 200 });

    // Third block references `x-new-indexed` inserted during the `TooLarge` block:
    // dynamic table must still be 100% synchronized!
    enc.encode(
        [
            EncodeField::new(b"x-cjk-greeting", cjk_value.as_bytes()),
            EncodeField::new(b"x-new-indexed", b"persists-across-too-large"),
        ],
        &mut buf,
    );
    let DecodeOutcome::Fields(third) = dec.decode(&buf.split().freeze(), 4096).unwrap() else {
        panic!("expected Fields after TooLarge");
    };
    assert_eq!(&third[0].value[..], cjk_value.as_bytes());
    assert_eq!(&third[1].value[..], b"persists-across-too-large");
    assert!(third[0].parsed_name.is_some());
    assert!(third[0].parsed_value.is_some());
}

#[test]
fn rejects_rfc7541_wire_errors() {
    let mut dec = Decoder::new(4096);
    // Index 0 (`0x80`) -> InvalidTableIndex
    assert_eq!(
        dec.decode(&Bytes::from_static(&[0x80]), 4096),
        Err(HpackError::InvalidTableIndex)
    );
    // Out-of-bounds index 62 on empty dynamic table (`0xBE`) -> InvalidTableIndex
    assert_eq!(
        dec.decode(&Bytes::from_static(&[0xBE]), 4096),
        Err(HpackError::InvalidTableIndex)
    );
    // Dynamic table size update after header field (`0x82` GET, then `0x20` size=0)
    assert_eq!(
        dec.decode(&Bytes::from_static(&[0x82, 0x20]), 4096),
        Err(HpackError::InvalidTableSizeUpdate)
    );
    // Dynamic table size update > SETTINGS_HEADER_TABLE_SIZE (`4097` > `4096`)
    let mut oversize = BytesMut::new();
    http_kit_h2::hpack::int::encode_int(4097, 5, 0x20, &mut oversize);
    assert_eq!(
        dec.decode(&oversize.freeze(), 4096),
        Err(HpackError::InvalidTableSizeUpdate)
    );
    // Missing mandatory dynamic table size reduction after SETTINGS_HEADER_TABLE_SIZE shrinks!
    let mut dec_shrink = Decoder::new(4096);
    dec_shrink.set_max_table_size(256);
    dec_shrink.set_max_table_size(1024);
    // Sending a header without first emitting size update <= 256 must fail!
    assert_eq!(
        dec_shrink.decode(&Bytes::from_static(&[0x82]), 4096),
        Err(HpackError::InvalidTableSizeUpdate)
    );
    // Sending update(256), update(1024), then `0x82` succeeds!
    let mut valid_updates = BytesMut::new();
    http_kit_h2::hpack::int::encode_int(256, 5, 0x20, &mut valid_updates);
    http_kit_h2::hpack::int::encode_int(1024, 5, 0x20, &mut valid_updates);
    valid_updates.extend_from_slice(&[0x82]);
    let mut dec_shrink_ok = Decoder::new(4096);
    dec_shrink_ok.set_max_table_size(256);
    dec_shrink_ok.set_max_table_size(1024);
    assert!(dec_shrink_ok.decode(&valid_updates.freeze(), 4096).is_ok());
}

#[derive(Debug, Deserialize)]
struct Story {
    cases: Vec<StoryCase>,
}

#[derive(Debug, Deserialize)]
struct StoryCase {
    #[serde(default)]
    seqno: Option<usize>,
    #[serde(default)]
    header_table_size: Option<u32>,
    #[serde(default)]
    wire: Option<String>,
    headers: Vec<serde_json::Map<String, serde_json::Value>>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

fn fetch_verified_hpack_tarball() -> Vec<u8> {
    let cache_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(&cache_dir).expect("create CARGO_TARGET_TMPDIR");
    let archive_path =
        cache_dir.join("hpack-test-case-8a1406e7d14bfcb6c046021f13cc15cfb162726d.tar.gz");

    if let Ok(cached) = fs::read(&archive_path)
        && sha256_hex(&cached) == HPACK_TEST_CASE_SHA256
    {
        return cached;
    }

    let tmp_path = cache_dir.join(format!("hpack-test-case-{}.part", std::process::id()));
    let status = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--retry",
            "3",
            "--output",
        ])
        .arg(&tmp_path)
        .arg(HPACK_TEST_CASE_URL)
        .status()
        .expect("spawn curl to fetch pinned http2jp/hpack-test-case tarball");
    assert!(
        status.success(),
        "curl failed fetching {HPACK_TEST_CASE_URL}: {status}"
    );

    let bytes = fs::read(&tmp_path).expect("read downloaded hpack-test-case tarball");
    let actual_sha = sha256_hex(&bytes);
    if actual_sha != HPACK_TEST_CASE_SHA256 {
        let _ = fs::remove_file(&tmp_path);
        panic!(
            "SHA-256 mismatch for {HPACK_TEST_CASE_URL}: expected {HPACK_TEST_CASE_SHA256}, got {actual_sha}"
        );
    }
    fs::rename(&tmp_path, &archive_path)
        .expect("atomically cache verified hpack-test-case tarball");
    bytes
}

#[test]
fn http2jp_hpack_test_case_decode_and_reencode_every_story() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let tarball = fetch_verified_hpack_tarball();
    let gz = GzDecoder::new(tarball.as_slice());
    let mut archive = Archive::new(gz);

    let mut stories: Vec<(PathBuf, bool, Vec<u8>)> = Vec::with_capacity(512);
    for entry in archive.entries().expect("read tar entries") {
        let mut entry = entry.expect("valid tar entry");
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path: PathBuf = entry.path().expect("utf-8 tar path").into_owned();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !file_name.starts_with("story_") {
            continue;
        }
        let suite = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let is_raw = suite == "raw-data";
        let mut json_bytes = Vec::new();
        entry.read_to_end(&mut json_bytes).unwrap();
        stories.push((path, is_raw, json_bytes));
    }

    let workers = std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1)
        .min(stories.len().max(1));
    let next_idx = AtomicUsize::new(0);
    let wire_stories = AtomicUsize::new(0);
    let raw_stories = AtomicUsize::new(0);
    let total_cases = AtomicUsize::new(0);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                let mut out_buf = BytesMut::new();
                loop {
                    let story_idx = next_idx.fetch_add(1, Ordering::Relaxed);
                    let Some((path, is_raw, json_bytes)) = stories.get(story_idx) else {
                        break;
                    };
                    let story: Story = serde_json::from_slice(json_bytes)
                        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));

                    if *is_raw {
                        raw_stories.fetch_add(1, Ordering::Relaxed);
                    } else {
                        wire_stories.fetch_add(1, Ordering::Relaxed);
                    }
                    total_cases.fetch_add(story.cases.len(), Ordering::Relaxed);

                    let mut wire_decoder = Decoder::new(4096);
                    let mut re_encoder = Encoder::new(16 * 1024);
                    let mut re_decoder = Decoder::new(4096);

                    for (idx, case) in story.cases.iter().enumerate() {
                        let seq = case.seqno.unwrap_or(idx);
                        let expected: Vec<(Bytes, Bytes)> = case
                            .headers
                            .iter()
                            .map(|map| {
                                assert_eq!(
                                    map.len(),
                                    1,
                                    "{} case {seq} header map len != 1",
                                    path.display(),
                                );
                                let (k, v) = map.iter().next().unwrap();
                                let v_str = v.as_str().expect("string header value");
                                (
                                    Bytes::copy_from_slice(k.as_bytes()),
                                    Bytes::copy_from_slice(v_str.as_bytes()),
                                )
                            })
                            .collect();

                        if let Some(new_max) = case.header_table_size {
                            wire_decoder.set_max_table_size(new_max);
                            re_encoder.set_peer_max_table_size(new_max);
                            re_decoder.set_max_table_size(new_max);
                        }

                        if !*is_raw {
                            let wire_hex = case.wire.as_deref().unwrap_or_else(|| {
                                panic!("{} case {seq} missing wire", path.display())
                            });
                            let wire = unhex(wire_hex);
                            let DecodeOutcome::Fields(decoded) =
                                wire_decoder.decode(&wire, u32::MAX).unwrap_or_else(|e| {
                                    panic!("decode failed in {} case {seq}: {e}", path.display())
                                })
                            else {
                                panic!("unexpected TooLarge in {}", path.display());
                            };
                            let got: Vec<(Bytes, Bytes)> =
                                decoded.into_iter().map(|f| (f.name, f.value)).collect();
                            assert_eq!(
                                got,
                                expected,
                                "wire decode mismatch in {} case {seq}",
                                path.display(),
                            );
                            assert!(
                                wire_decoder.dynamic_table_size()
                                    <= wire_decoder.dynamic_table_max_size()
                            );
                        }

                        out_buf.clear();
                        re_encoder.encode(
                            expected
                                .iter()
                                .map(|(k, v)| EncodeField::new(k.as_ref(), v.as_ref())),
                            &mut out_buf,
                        );
                        let re_wire = out_buf.split().freeze();
                        let DecodeOutcome::Fields(re_decoded) =
                            re_decoder.decode(&re_wire, u32::MAX).unwrap_or_else(|e| {
                                panic!(
                                    "re-encoded block failed to decode in {} case {seq}: {e}",
                                    path.display(),
                                )
                            })
                        else {
                            panic!("unexpected TooLarge on re-encode");
                        };
                        let re_got: Vec<(Bytes, Bytes)> =
                            re_decoded.into_iter().map(|f| (f.name, f.value)).collect();
                        assert_eq!(
                            re_got,
                            expected,
                            "re-encode mismatch in {} case {seq}",
                            path.display(),
                        );
                    }
                }
            });
        }
    });

    let wire_stories = wire_stories.load(Ordering::Relaxed);
    let raw_stories = raw_stories.load(Ordering::Relaxed);
    let total_cases = total_cases.load(Ordering::Relaxed);
    assert!(
        wire_stories >= 300 && raw_stories >= 20 && total_cases >= 10_000,
        "expected full http2jp/hpack-test-case corpus, got wire_stories={wire_stories}, raw_stories={raw_stories}, total_cases={total_cases}"
    );
}
