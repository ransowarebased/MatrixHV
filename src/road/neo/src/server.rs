use self::protocol::{Request, RequestKind, Response, read_request, write_response};
use std::io;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;

pub const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:4040";
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CAPTURED_STREAM_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum ServerExit {
    Update,
}

pub fn serve(
    listen_address: &str,
    mut prepare_update: impl FnMut(&[u8]) -> Result<(), String>,
    mut collect_telemetry: impl FnMut(u32, u32) -> Result<String, String>,
) -> Result<ServerExit, String> {
    let listener = TcpListener::bind(listen_address)
        .map_err(|error| format!("failed to bind {listen_address}: {error}"))?;
    println!("neo listening on {listen_address} (plaintext, unauthenticated)");

    loop {
        let (mut stream, peer_address) = listener
            .accept()
            .map_err(|error| format!("failed to accept a connection: {error}"))?;
        if let Err(error) = configure_stream(&stream) {
            eprintln!("connection from {peer_address} rejected: {error}");
            continue;
        }
        match handle_connection(&mut stream, &mut prepare_update, &mut collect_telemetry) {
            Ok(true) => return Ok(ServerExit::Update),
            Ok(false) => {}
            Err(error) => eprintln!("connection from {peer_address} failed: {error}"),
        }
    }
}

fn configure_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))
}

fn handle_connection(
    stream: &mut TcpStream,
    prepare_update: &mut impl FnMut(&[u8]) -> Result<(), String>,
    collect_telemetry: &mut impl FnMut(u32, u32) -> Result<String, String>,
) -> Result<bool, String> {
    let (request_id, request) = read_request(stream).map_err(|error| error.to_string())?;
    let (response, update) = match request {
        Request::Ping => (Response::success(RequestKind::Ping, "pong"), None),
        Request::Status => (Response::success(RequestKind::Status, status_text()), None),
        Request::Exec { arguments } => (execute(arguments), None),
        Request::Telemetry { mode, control } => {
            let response = match collect_telemetry(mode, control) {
                Ok(snapshot) => Response::success(RequestKind::Telemetry, snapshot),
                Err(error) => Response::failure(RequestKind::Telemetry, error),
            };
            (response, None)
        }
        Request::Update { binary } => {
            let response =
                match validate_update_binary(&binary).and_then(|()| prepare_update(&binary)) {
                    Ok(()) => Response::success(RequestKind::Update, "update accepted"),
                    Err(error) => Response::failure(RequestKind::Update, error),
                };
            let update = response.success.then_some(());
            (response, update)
        }
    };
    write_response(stream, request_id, &response).map_err(|error| error.to_string())?;
    Ok(update.is_some())
}

pub fn status_text() -> String {
    let status = hypervisor::query();
    let binary_fingerprint = current_binary_fingerprint()
        .map(|fingerprint| format!("{fingerprint:016x}"))
        .unwrap_or_else(|_| "unavailable".to_string());
    let mut text = format!(
        "agent=neo\nversion={}\nprocess_id={}\nbinary_fingerprint={}\nos={}\narch={}\nhypervisor_present={}\nhypervisor_vendor={}\nmatrixhv_present={}\nmatrixhv_protocol={}\n",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        binary_fingerprint,
        std::env::consts::OS,
        std::env::consts::ARCH,
        status.hypervisor_present,
        status.hypervisor_vendor,
        status.matrixhv_present,
        status.matrixhv_protocol,
    );
    text.push_str(&crate::telemetry::capability_status(
        status.matrixhv_present,
        status.matrixhv_protocol,
    ));
    text
}

fn current_binary_fingerprint() -> Result<u64, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("failed to resolve the neo executable: {error}"))?;
    let mut file = std::fs::File::open(&executable)
        .map_err(|error| format!("failed to open {}: {error}", executable.display()))?;
    let mut fingerprint = 0xcbf2_9ce4_8422_2325u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to read {}: {error}", executable.display()))?;
        if count == 0 {
            return Ok(fingerprint);
        }
        for byte in &buffer[..count] {
            fingerprint ^= u64::from(*byte);
            fingerprint = fingerprint.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

pub fn ping_text() -> String {
    "pong".to_string()
}

fn execute(arguments: Vec<String>) -> Response {
    let Some((program, program_arguments)) = arguments.split_first() else {
        return Response::failure(RequestKind::Exec, "no executable was provided");
    };
    match Command::new(program).args(program_arguments).output() {
        Ok(output) => {
            let exit_code = output.status.code();
            let success = output.status.success();
            Response {
                request_kind: RequestKind::Exec,
                success,
                exit_code,
                message: if success {
                    "process completed".to_string()
                } else {
                    "process failed".to_string()
                },
                stdout: truncate(output.stdout),
                stderr: truncate(output.stderr),
            }
        }
        Err(error) => Response::failure(
            RequestKind::Exec,
            format!("failed to start {program}: {error}"),
        ),
    }
}

fn truncate(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() > MAX_CAPTURED_STREAM_SIZE {
        bytes.truncate(MAX_CAPTURED_STREAM_SIZE);
    }
    bytes
}

fn validate_update_binary(binary: &[u8]) -> Result<(), String> {
    if binary.is_empty() {
        return Err("update binary is empty".to_string());
    }
    #[cfg(target_os = "windows")]
    if !binary.starts_with(b"MZ") {
        return Err("update is not a Windows PE executable".to_string());
    }
    #[cfg(target_os = "linux")]
    if !binary.starts_with(b"\x7fELF") {
        return Err("update is not a Linux ELF executable".to_string());
    }
    Ok(())
}

pub mod protocol {
    use std::io::{self, Read, Write};

    const MAGIC: [u8; 4] = *b"ROAD";
    pub const PROTOCOL_VERSION: u16 = 1;
    pub const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;
    const HEADER_SIZE: usize = 20;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u16)]
    pub enum RequestKind {
        Ping = 1,
        Status = 2,
        Exec = 3,
        Update = 4,
        Telemetry = 5,
    }

    impl TryFrom<u16> for RequestKind {
        type Error = ProtocolError;

        fn try_from(value: u16) -> Result<Self, Self::Error> {
            match value {
                1 => Ok(Self::Ping),
                2 => Ok(Self::Status),
                3 => Ok(Self::Exec),
                4 => Ok(Self::Update),
                5 => Ok(Self::Telemetry),
                _ => Err(ProtocolError::InvalidKind(value)),
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum Request {
        Ping,
        Status,
        Exec { arguments: Vec<String> },
        Update { binary: Vec<u8> },
        Telemetry { mode: u32, control: u32 },
    }

    impl Request {
        pub fn kind(&self) -> RequestKind {
            match self {
                Self::Ping => RequestKind::Ping,
                Self::Status => RequestKind::Status,
                Self::Exec { .. } => RequestKind::Exec,
                Self::Update { .. } => RequestKind::Update,
                Self::Telemetry { .. } => RequestKind::Telemetry,
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Response {
        pub request_kind: RequestKind,
        pub success: bool,
        pub exit_code: Option<i32>,
        pub message: String,
        pub stdout: Vec<u8>,
        pub stderr: Vec<u8>,
    }

    impl Response {
        pub fn success(request_kind: RequestKind, message: impl Into<String>) -> Self {
            Self {
                request_kind,
                success: true,
                exit_code: None,
                message: message.into(),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }

        pub fn failure(request_kind: RequestKind, message: impl Into<String>) -> Self {
            Self {
                request_kind,
                success: false,
                exit_code: None,
                message: message.into(),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }
    }

    #[derive(Debug)]
    pub enum ProtocolError {
        Io(io::Error),
        InvalidMagic,
        InvalidVersion(u16),
        InvalidKind(u16),
        InvalidResponseKind(u16),
        FrameTooLarge(usize),
        TruncatedPayload,
        InvalidUtf8,
        InvalidPayload(&'static str),
    }

    impl std::fmt::Display for ProtocolError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Io(error) => write!(formatter, "I/O error: {error}"),
                Self::InvalidMagic => formatter.write_str("invalid ROAD frame magic"),
                Self::InvalidVersion(version) => {
                    write!(formatter, "unsupported ROAD protocol version {version}")
                }
                Self::InvalidKind(kind) => write!(formatter, "unknown ROAD request kind {kind}"),
                Self::InvalidResponseKind(kind) => {
                    write!(formatter, "invalid ROAD response kind {kind}")
                }
                Self::FrameTooLarge(size) => {
                    write!(formatter, "ROAD frame size {size} exceeds the limit")
                }
                Self::TruncatedPayload => formatter.write_str("truncated ROAD payload"),
                Self::InvalidUtf8 => formatter.write_str("ROAD payload contains invalid UTF-8"),
                Self::InvalidPayload(reason) => write!(formatter, "invalid ROAD payload: {reason}"),
            }
        }
    }

    impl std::error::Error for ProtocolError {}

    impl From<io::Error> for ProtocolError {
        fn from(error: io::Error) -> Self {
            Self::Io(error)
        }
    }

    pub fn write_request(
        writer: &mut impl Write,
        request_id: u64,
        request: &Request,
    ) -> Result<(), ProtocolError> {
        let mut payload = Vec::new();
        match request {
            Request::Ping | Request::Status => {}
            Request::Telemetry { mode, control } => {
                put_u32(&mut payload, *mode);
                put_u32(&mut payload, *control);
            }
            Request::Exec { arguments } => {
                let count = u32::try_from(arguments.len())
                    .map_err(|_| ProtocolError::InvalidPayload("too many command arguments"))?;
                put_u32(&mut payload, count);
                for argument in arguments {
                    put_bytes(&mut payload, argument.as_bytes())?;
                }
            }
            Request::Update { binary } => put_bytes(&mut payload, binary)?,
        }
        write_frame(writer, request.kind() as u16, request_id, &payload)
    }

    pub fn read_request(reader: &mut impl Read) -> Result<(u64, Request), ProtocolError> {
        let (raw_kind, request_id, payload) = read_frame(reader)?;
        let kind = RequestKind::try_from(raw_kind)?;
        let mut cursor = Cursor::new(&payload);
        let request = match kind {
            RequestKind::Ping => Request::Ping,
            RequestKind::Status => Request::Status,
            RequestKind::Exec => {
                let count = cursor.read_u32()? as usize;
                if count == 0 || count > 4096 {
                    return Err(ProtocolError::InvalidPayload(
                        "invalid command argument count",
                    ));
                }
                let mut arguments = Vec::with_capacity(count);
                for _ in 0..count {
                    let bytes = cursor.read_bytes()?;
                    let argument = String::from_utf8(bytes.to_vec())
                        .map_err(|_| ProtocolError::InvalidUtf8)?;
                    arguments.push(argument);
                }
                Request::Exec { arguments }
            }
            RequestKind::Update => Request::Update {
                binary: cursor.read_bytes()?.to_vec(),
            },
            RequestKind::Telemetry => {
                if payload.is_empty() {
                    Request::Telemetry {
                        mode: 0,
                        control: 0,
                    }
                } else {
                    Request::Telemetry {
                        mode: cursor.read_u32()?,
                        control: cursor.read_u32()?,
                    }
                }
            }
        };
        cursor.finish()?;
        Ok((request_id, request))
    }

    pub fn write_response(
        writer: &mut impl Write,
        request_id: u64,
        response: &Response,
    ) -> Result<(), ProtocolError> {
        let mut payload = Vec::new();
        put_u32(&mut payload, u32::from(!response.success));
        put_i32(&mut payload, response.exit_code.unwrap_or(i32::MIN));
        put_bytes(&mut payload, response.message.as_bytes())?;
        put_bytes(&mut payload, &response.stdout)?;
        put_bytes(&mut payload, &response.stderr)?;
        write_frame(
            writer,
            0x8000 | response.request_kind as u16,
            request_id,
            &payload,
        )
    }

    pub fn read_response(reader: &mut impl Read) -> Result<(u64, Response), ProtocolError> {
        let (raw_kind, request_id, payload) = read_frame(reader)?;
        if raw_kind & 0x8000 == 0 {
            return Err(ProtocolError::InvalidResponseKind(raw_kind));
        }
        let request_kind = RequestKind::try_from(raw_kind & 0x7fff)?;
        let mut cursor = Cursor::new(&payload);
        let success = cursor.read_u32()? == 0;
        let raw_exit_code = cursor.read_i32()?;
        let message = String::from_utf8(cursor.read_bytes()?.to_vec())
            .map_err(|_| ProtocolError::InvalidUtf8)?;
        let stdout = cursor.read_bytes()?.to_vec();
        let stderr = cursor.read_bytes()?.to_vec();
        cursor.finish()?;
        Ok((
            request_id,
            Response {
                request_kind,
                success,
                exit_code: (raw_exit_code != i32::MIN).then_some(raw_exit_code),
                message,
                stdout,
                stderr,
            },
        ))
    }

    fn write_frame(
        writer: &mut impl Write,
        kind: u16,
        request_id: u64,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        if payload.len() > MAX_FRAME_SIZE {
            return Err(ProtocolError::FrameTooLarge(payload.len()));
        }
        let payload_size = u32::try_from(payload.len())
            .map_err(|_| ProtocolError::FrameTooLarge(payload.len()))?;
        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        header[6..8].copy_from_slice(&kind.to_le_bytes());
        header[8..12].copy_from_slice(&payload_size.to_le_bytes());
        header[12..20].copy_from_slice(&request_id.to_le_bytes());
        writer.write_all(&header)?;
        writer.write_all(payload)?;
        writer.flush()?;
        Ok(())
    }

    fn read_frame(reader: &mut impl Read) -> Result<(u16, u64, Vec<u8>), ProtocolError> {
        let mut header = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header)?;
        if header[0..4] != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        let version = u16::from_le_bytes([header[4], header[5]]);
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidVersion(version));
        }
        let kind = u16::from_le_bytes([header[6], header[7]]);
        let payload_size = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        if payload_size > MAX_FRAME_SIZE {
            return Err(ProtocolError::FrameTooLarge(payload_size));
        }
        let request_id = u64::from_le_bytes(header[12..20].try_into().unwrap());
        let mut payload = vec![0u8; payload_size];
        reader.read_exact(&mut payload)?;
        Ok((kind, request_id, payload))
    }

    fn put_u32(buffer: &mut Vec<u8>, value: u32) {
        buffer.extend_from_slice(&value.to_le_bytes());
    }

    fn put_i32(buffer: &mut Vec<u8>, value: i32) {
        buffer.extend_from_slice(&value.to_le_bytes());
    }

    fn put_bytes(buffer: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolError> {
        let size =
            u32::try_from(value.len()).map_err(|_| ProtocolError::FrameTooLarge(value.len()))?;
        put_u32(buffer, size);
        buffer.extend_from_slice(value);
        Ok(())
    }

    struct Cursor<'a> {
        payload: &'a [u8],
        offset: usize,
    }

    impl<'a> Cursor<'a> {
        fn new(payload: &'a [u8]) -> Self {
            Self { payload, offset: 0 }
        }

        fn read_u32(&mut self) -> Result<u32, ProtocolError> {
            let bytes = self.take(4)?;
            Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
        }

        fn read_i32(&mut self) -> Result<i32, ProtocolError> {
            let bytes = self.take(4)?;
            Ok(i32::from_le_bytes(bytes.try_into().unwrap()))
        }

        fn read_bytes(&mut self) -> Result<&'a [u8], ProtocolError> {
            let size = self.read_u32()? as usize;
            self.take(size)
        }

        fn take(&mut self, size: usize) -> Result<&'a [u8], ProtocolError> {
            let end = self
                .offset
                .checked_add(size)
                .ok_or(ProtocolError::TruncatedPayload)?;
            let bytes = self
                .payload
                .get(self.offset..end)
                .ok_or(ProtocolError::TruncatedPayload)?;
            self.offset = end;
            Ok(bytes)
        }

        fn finish(self) -> Result<(), ProtocolError> {
            if self.offset == self.payload.len() {
                Ok(())
            } else {
                Err(ProtocolError::InvalidPayload("trailing bytes"))
            }
        }
    }
}
pub mod hypervisor {
    use crate::protocol::{
        MATRIXHV_STATUS_LEAF, MATRIXHV_STATUS_SIGNATURE_EAX, MATRIXHV_STATUS_SIGNATURE_EBX,
        MATRIXHV_STATUS_SIGNATURE_ECX,
    };
    #[derive(Debug)]
    pub struct HypervisorStatus {
        pub hypervisor_present: bool,
        pub hypervisor_vendor: String,
        pub matrixhv_present: bool,
        pub matrixhv_protocol: u32,
    }

    const HYPERVISOR_PRESENT_BIT: u32 = 1 << 31;
    const HYPERVISOR_VENDOR_LEAF: u32 = 0x4000_0000;

    pub fn query() -> HypervisorStatus {
        #[cfg(target_arch = "x86_64")]
        {
            use std::arch::x86_64::__cpuid_count;

            let feature = __cpuid_count(1, 0);
            let hypervisor_present = feature.ecx & HYPERVISOR_PRESENT_BIT != 0;
            let vendor = if hypervisor_present {
                let result = __cpuid_count(HYPERVISOR_VENDOR_LEAF, 0);
                let mut bytes = Vec::with_capacity(12);
                bytes.extend_from_slice(&result.ebx.to_le_bytes());
                bytes.extend_from_slice(&result.ecx.to_le_bytes());
                bytes.extend_from_slice(&result.edx.to_le_bytes());
                String::from_utf8_lossy(&bytes)
                    .trim_end_matches('\0')
                    .to_string()
            } else {
                "none".to_string()
            };
            let matrixhv = __cpuid_count(MATRIXHV_STATUS_LEAF, 0);
            let matrixhv_present = matrixhv.eax == MATRIXHV_STATUS_SIGNATURE_EAX
                && matrixhv.ebx == MATRIXHV_STATUS_SIGNATURE_EBX
                && matrixhv.ecx == MATRIXHV_STATUS_SIGNATURE_ECX;
            HypervisorStatus {
                hypervisor_present,
                hypervisor_vendor: vendor,
                matrixhv_present,
                matrixhv_protocol: if matrixhv_present { matrixhv.edx } else { 0 },
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        HypervisorStatus {
            hypervisor_present: false,
            hypervisor_vendor: "unsupported-architecture".to_string(),
            matrixhv_present: false,
            matrixhv_protocol: 0,
        }
    }
}
