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
}

impl TryFrom<u16> for RequestKind {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ping),
            2 => Ok(Self::Status),
            3 => Ok(Self::Exec),
            4 => Ok(Self::Update),
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
}

impl Request {
    pub fn kind(&self) -> RequestKind {
        match self {
            Self::Ping => RequestKind::Ping,
            Self::Status => RequestKind::Status,
            Self::Exec { .. } => RequestKind::Exec,
            Self::Update { .. } => RequestKind::Update,
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
                let argument =
                    String::from_utf8(bytes.to_vec()).map_err(|_| ProtocolError::InvalidUtf8)?;
                arguments.push(argument);
            }
            Request::Exec { arguments }
        }
        RequestKind::Update => Request::Update {
            binary: cursor.read_bytes()?.to_vec(),
        },
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
    let message =
        String::from_utf8(cursor.read_bytes()?.to_vec()).map_err(|_| ProtocolError::InvalidUtf8)?;
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
    let payload_size =
        u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge(payload.len()))?;
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
    let size = u32::try_from(value.len()).map_err(|_| ProtocolError::FrameTooLarge(value.len()))?;
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
