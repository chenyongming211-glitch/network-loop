use std::io;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::MAX_PAYLOAD_LEN;

const LENGTH_PREFIX_LEN: usize = 4;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("frame ended early: declared {declared} bytes, received {received}")]
    EarlyEof { declared: usize, received: usize },
    #[error("payload length {declared} exceeds maximum {maximum}")]
    PayloadTooLarge { declared: usize, maximum: usize },
    #[error("control transport I/O failed")]
    Io(#[source] io::Error),
}

pub async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>, TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; LENGTH_PREFIX_LEN];
    let prefix_received = read_bounded(reader, &mut prefix)
        .await
        .map_err(TransportError::Io)?;
    if prefix_received != LENGTH_PREFIX_LEN {
        return Err(TransportError::EarlyEof {
            declared: LENGTH_PREFIX_LEN,
            received: prefix_received,
        });
    }

    let declared = u32::from_be_bytes(prefix) as usize;
    if declared > MAX_PAYLOAD_LEN {
        return Err(TransportError::PayloadTooLarge {
            declared,
            maximum: MAX_PAYLOAD_LEN,
        });
    }

    let mut frame = vec![0_u8; LENGTH_PREFIX_LEN + declared];
    frame[..LENGTH_PREFIX_LEN].copy_from_slice(&prefix);
    let payload_received = read_bounded(reader, &mut frame[LENGTH_PREFIX_LEN..])
        .await
        .map_err(TransportError::Io)?;
    if payload_received != declared {
        return Err(TransportError::EarlyEof {
            declared,
            received: payload_received,
        });
    }

    Ok(frame)
}

pub async fn write_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(frame).await.map_err(TransportError::Io)?;
    writer.flush().await.map_err(TransportError::Io)
}

async fn read_bounded<R>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize>
where
    R: AsyncRead + Unpin,
{
    let mut received = 0;
    while received < buffer.len() {
        let count = reader.read(&mut buffer[received..]).await?;
        if count == 0 {
            break;
        }
        received += count;
    }
    Ok(received)
}
