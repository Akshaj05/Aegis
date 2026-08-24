// Length-prefixed framing for sending/receiving WorkerRequest and
// WorkerResponse messages over a UnixStream.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use serde::de::DeserializeOwned;
use serde::Serialize;

const MAX_MESSAGE_BYTES: u32 = 16 * 1024 * 1024;

pub fn send_message<T: Serialize>(stream: &UnixStream, msg: &T) -> io::Result<()> {
    let bytes =
        serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too large to frame"))?;
    let mut stream = stream;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()
}

pub fn recv_message<T: DeserializeOwned>(stream: &UnixStream) -> io::Result<T> {
    let mut stream = stream;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message exceeds maximum frame size",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::worker::protocol::{FileKind, StatInfo, WorkerRequest, WorkerResponse};

    #[test]
    fn sends_and_receives_a_request_over_a_real_socketpair() {
        let (a, b) = UnixStream::pair().unwrap();
        let request = WorkerRequest::ReadFile {
            rel_path: "project/README".into(),
        };
        send_message(&a, &request).unwrap();
        let received: WorkerRequest = recv_message(&b).unwrap();
        assert_eq!(request, received);
    }

    #[test]
    fn sends_and_receives_a_response_over_a_real_socketpair() {
        let (a, b) = UnixStream::pair().unwrap();
        let response = WorkerResponse::Stat(StatInfo {
            kind: FileKind::Regular,
            len: 42,
        });
        send_message(&a, &response).unwrap();
        let received: WorkerResponse = recv_message(&b).unwrap();
        assert_eq!(response, received);
    }

    #[test]
    fn multiple_messages_in_sequence_do_not_interleave() {
        let (a, b) = UnixStream::pair().unwrap();
        send_message(
            &a,
            &WorkerRequest::Stat {
                rel_path: "one".into(),
            },
        )
        .unwrap();
        send_message(
            &a,
            &WorkerRequest::Stat {
                rel_path: "two".into(),
            },
        )
        .unwrap();

        let first: WorkerRequest = recv_message(&b).unwrap();
        let second: WorkerRequest = recv_message(&b).unwrap();
        assert_eq!(
            first,
            WorkerRequest::Stat {
                rel_path: "one".into()
            }
        );
        assert_eq!(
            second,
            WorkerRequest::Stat {
                rel_path: "two".into()
            }
        );
    }

    #[test]
    fn oversized_length_prefix_is_rejected_before_allocating() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(&(MAX_MESSAGE_BYTES + 1).to_be_bytes()).unwrap();
        let result: io::Result<WorkerRequest> = recv_message(&b);
        assert!(result.is_err());
    }
}
