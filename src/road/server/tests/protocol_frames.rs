use road_server::protocol::{
    Request, RequestKind, Response, read_request, read_response, write_request, write_response,
};

#[test]
fn exec_request_round_trips_without_command_line_reconstruction() {
    let request = Request::Exec {
        arguments: vec![
            "powershell.exe".to_string(),
            "-Command".to_string(),
            "Write-Output 'two words'".to_string(),
        ],
    };
    let mut bytes = Vec::new();
    write_request(&mut bytes, 42, &request).unwrap();
    let (request_id, decoded) = read_request(&mut bytes.as_slice()).unwrap();
    assert_eq!(request_id, 42);
    assert_eq!(decoded, request);
}

#[test]
fn process_response_preserves_binary_streams_and_exit_code() {
    let response = Response {
        request_kind: RequestKind::Exec,
        success: false,
        exit_code: Some(7),
        message: "process exited".to_string(),
        stdout: vec![0, 1, 2, 255],
        stderr: b"failure".to_vec(),
    };
    let mut bytes = Vec::new();
    write_response(&mut bytes, 9, &response).unwrap();
    let (request_id, decoded) = read_response(&mut bytes.as_slice()).unwrap();
    assert_eq!(request_id, 9);
    assert_eq!(decoded, response);
}

#[test]
fn update_request_preserves_binary_bytes() {
    let request = Request::Update {
        binary: vec![0x7f, b'E', b'L', b'F', 0, 255],
    };
    let mut bytes = Vec::new();
    write_request(&mut bytes, u64::MAX, &request).unwrap();
    let (_, decoded) = read_request(&mut bytes.as_slice()).unwrap();
    assert_eq!(decoded, request);
}
