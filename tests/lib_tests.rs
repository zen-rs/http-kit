use http_kit::{Body, Error, Result, ResultExt, StatusCode};
// Import stream specifically for the one function that needs it
use futures_lite::StreamExt;

#[tokio::test]
async fn test_basic_body_operations() {
    // Test empty body
    let empty = Body::empty();
    assert_eq!(empty.len(), Some(0));
    assert_eq!(empty.is_empty(), Some(true));
    assert!(!empty.is_frozen());

    // Test body from string
    let text_body = Body::from_bytes("Hello, World!");
    assert_eq!(text_body.len(), Some(13));
    assert_eq!(text_body.is_empty(), Some(false));

    let result = text_body.into_bytes().await.unwrap();
    assert_eq!(result.as_ref(), b"Hello, World!");
}

#[tokio::test]
async fn test_body_freeze_and_take() {
    let mut body = Body::from_bytes("test data");
    assert!(!body.is_frozen());

    // Test take using the correct method from Body, not Stream
    let taken = Body::take(&mut body).unwrap();
    assert!(body.is_frozen());

    // Test that taken body works
    let data = taken.into_bytes().await.unwrap();
    assert_eq!(data.as_ref(), b"test data");

    // Test that frozen body fails
    let result = body.into_bytes().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_body_conversions() {
    // Test from Vec<u8>
    let vec_data = vec![1, 2, 3, 4, 5];
    let body = Body::from(vec_data.clone());
    let result = body.into_bytes().await.unwrap();
    assert_eq!(result.as_ref(), vec_data.as_slice());

    // Test from &str
    let str_data = "string conversion test";
    let body = Body::from(str_data);
    let result = body.into_string().await.unwrap();
    assert_eq!(result.as_str(), str_data);

    // Test from String
    let string_data = "owned string test".to_string();
    let expected = string_data.clone();
    let body = Body::from(string_data);
    let result = body.into_string().await.unwrap();
    assert_eq!(result.as_str(), expected);

    // Test from &[u8]
    let slice_data: &[u8] = &[6, 7, 8, 9, 10];
    let body = Body::from(slice_data);
    let result = body.into_bytes().await.unwrap();
    assert_eq!(result.as_ref(), slice_data);
}

#[tokio::test]
async fn test_body_stream() {
    let body = Body::from_bytes("streaming test data");
    let mut chunks = Vec::new();

    let mut stream = body;
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.unwrap();
        chunks.push(chunk);
    }

    // For a bytes body, should get all data in one chunk
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].as_ref(), b"streaming test data");
}

#[cfg(feature = "json")]
#[tokio::test]
async fn test_json_functionality() {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct TestData {
        message: String,
        count: u32,
    }

    let data = TestData {
        message: "JSON test".to_string(),
        count: 42,
    };

    // Test serialization
    let body = Body::from_json(&data).unwrap();
    let json_str = body.into_string().await.unwrap();
    assert!(json_str.contains("JSON test"));
    assert!(json_str.contains("42"));

    // Test deserialization
    let mut body = Body::from_json(&data).unwrap();
    let parsed: TestData = body.into_json().await.unwrap();
    assert_eq!(parsed, data);
}

#[cfg(feature = "form")]
#[tokio::test]
async fn test_form_functionality() {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct FormData {
        name: String,
        age: u32,
    }

    let data = FormData {
        name: "Alice".to_string(),
        age: 30,
    };

    // Test serialization
    let body = Body::from_form(&data).unwrap();
    let form_str = body.into_string().await.unwrap();
    assert!(form_str.contains("name=Alice"));
    assert!(form_str.contains("age=30"));

    // Test deserialization
    let mut body = Body::from_form(&data).unwrap();
    let parsed: FormData = body.into_form().await.unwrap();
    assert_eq!(parsed, data);
}

#[tokio::test]
async fn test_error_functionality() {
    // Test basic error creation
    let error = Error::msg("Test error");
    assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(format!("{}", error), "Test error");

    // Test error with custom status
    let error_404 = Error::msg("Not found").set_status(StatusCode::NOT_FOUND);
    assert_eq!(error_404.status(), StatusCode::NOT_FOUND);
    assert_eq!(format!("{}", error_404), "Not found");

    // Test error from standard error
    let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let http_error = Error::new(io_error, StatusCode::NOT_FOUND);
    assert_eq!(http_error.status(), StatusCode::NOT_FOUND);

    // Test downcast
    let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
    let error = Error::new(io_error, StatusCode::FORBIDDEN);
    let downcasted = error.downcast_ref::<std::io::Error>().unwrap();
    assert_eq!(downcasted.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn test_from_impl_sets_default_status() {
    fn fallible() -> Result<()> {
        Err(std::io::Error::other("permission denied")).status(500)?;
        Ok(())
    }

    let err = fallible().unwrap_err();
    assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(err.to_string(), "permission denied");
}

#[tokio::test]
async fn test_result_ext_functionality() {
    use http_kit::ResultExt;

    // Test with Result
    let io_result: std::result::Result<String, std::io::Error> = Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "file not found",
    ));

    let http_result: Result<String> = io_result.status(StatusCode::NOT_FOUND);
    assert!(http_result.is_err());

    let error = http_result.unwrap_err();
    assert_eq!(error.status(), StatusCode::NOT_FOUND);

    // Test with Option (None)
    let option: Option<i32> = None;
    let result: Result<i32> = option.status(StatusCode::BAD_REQUEST);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);

    // Test with Option (Some)
    let option: Option<i32> = Some(42);
    let result: Result<i32> = option.status(StatusCode::BAD_REQUEST);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
}



// Test that runs the code that was previously buggy
#[tokio::test]
async fn test_reader_no_infinite_loop() {
    use futures_lite::{io::BufReader, io::Cursor};

    let data = "This test ensures the reader doesn't create infinite loops";
    let cursor = Cursor::new(data.as_bytes().to_vec());
    let reader = BufReader::new(cursor);

    let body = Body::from_reader(reader, data.len());

    // This should complete without hanging
    let result = body.into_bytes().await.unwrap();
    assert_eq!(result.as_ref(), data.as_bytes());
}

// Test SSE functionality if implemented
#[tokio::test]
async fn test_sse_basic() {
    // Just ensure the from_sse function exists and doesn't panic
    // We'll create a simple stream for testing
    let events = futures_lite::stream::iter(vec![
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
            http_kit::sse::Event::from_data("test data").with_id("1"),
        ),
        Ok(http_kit::sse::Event::from_data("more data").with_id("2")),
    ]);

    let _body = Body::from_sse(events);
    // If we get here without panicking, the SSE implementation is at least syntactically correct
}

#[tokio::test]
async fn test_body_as_str_and_bytes() {
    let mut body = Body::from_bytes("test string");

    // Test as_bytes
    let bytes_ref = body.as_bytes().await.unwrap();
    assert_eq!(bytes_ref, b"test string");

    // Should be able to call multiple times on the same body
    let bytes_ref2 = body.as_bytes().await.unwrap();
    assert_eq!(bytes_ref2, b"test string");

    // Test as_str on new body
    let mut body2 = Body::from_bytes("test string");
    let str_ref = body2.as_str().await.unwrap();
    assert_eq!(str_ref, "test string");

    // Test invalid UTF-8
    let mut invalid_body = Body::from_bytes(vec![0xFF, 0xFE, 0xFD]);
    let result = invalid_body.as_str().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_body_replace_and_swap() {
    // Test replace
    let mut body = Body::from_bytes("original");
    let old_body = body.replace(Body::from_bytes("replacement"));

    let new_data = body.into_bytes().await.unwrap();
    let old_data = old_body.into_bytes().await.unwrap();

    assert_eq!(new_data.as_ref(), b"replacement");
    assert_eq!(old_data.as_ref(), b"original");

    // Test swap
    let mut body1 = Body::from_bytes("first");
    let mut body2 = Body::from_bytes("second");

    Body::swap(&mut body1, &mut body2).unwrap();

    let data1 = body1.into_bytes().await.unwrap();
    let data2 = body2.into_bytes().await.unwrap();

    assert_eq!(data1.as_ref(), b"second");
    assert_eq!(data2.as_ref(), b"first");

    // Test swap on frozen body should fail
    let mut frozen_body = Body::frozen();
    let mut normal_body = Body::from_bytes("test");
    let result = Body::swap(&mut frozen_body, &mut normal_body);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_body_freeze() {
    let mut body = Body::from_bytes("test");
    assert!(!body.is_frozen());

    body.freeze();
    assert!(body.is_frozen());

    let result = body.into_bytes().await;
    assert!(result.is_err());
}
