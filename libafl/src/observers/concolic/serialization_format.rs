#![cfg(feature = "std")]

use std::io::{self, Read, Seek, SeekFrom, Write};

use bincode::{DefaultOptions, Options};

use super::{SymExpr, SymExprRef};

pub use bincode::ErrorKind;
pub use bincode::Result;

fn serialization_options() -> DefaultOptions {
    DefaultOptions::new()
}
pub struct MessageFileReader<R: Read> {
    reader: R,
    deserializer_config: bincode::DefaultOptions,
    current_id: usize,
}

impl<R: Read> MessageFileReader<R> {
    pub fn from_reader(reader: R) -> Self {
        Self {
            reader,
            deserializer_config: serialization_options(),
            current_id: 1,
        }
    }

    pub fn next_message(&mut self) -> Option<bincode::Result<(SymExprRef, SymExpr)>> {
        match self.deserializer_config.deserialize_from(&mut self.reader) {
            Ok(mut message) => {
                if let SymExpr::End = message {
                    None
                } else {
                    let message_id = self.transform_message(&mut message);
                    Some(Ok((message_id, message)))
                }
            }
            Err(e) => match *e {
                bincode::ErrorKind::Io(ref io_err) => match io_err.kind() {
                    io::ErrorKind::UnexpectedEof => None,
                    _ => Some(Err(e)),
                },
                _ => Some(Err(e)),
            },
        }
    }

    fn make_absolute(&self, expr: SymExprRef) -> SymExprRef {
        SymExprRef::new(self.current_id - expr.get()).unwrap()
    }

    fn transform_message(&mut self, message: &mut SymExpr) -> SymExprRef {
        let ret = self.current_id;
        match message {
            SymExpr::InputByte { .. }
            | SymExpr::Integer { .. }
            | SymExpr::Integer128 { .. }
            | SymExpr::Float { .. }
            | SymExpr::NullPointer
            | SymExpr::True
            | SymExpr::False
            | SymExpr::Bool { .. } => {
                self.current_id += 1;
            }
            SymExpr::Neg { op }
            | SymExpr::FloatAbs { op }
            | SymExpr::Not { op }
            | SymExpr::Sext { op, .. }
            | SymExpr::Zext { op, .. }
            | SymExpr::Trunc { op, .. }
            | SymExpr::IntToFloat { op, .. }
            | SymExpr::FloatToFloat { op, .. }
            | SymExpr::BitsToFloat { op, .. }
            | SymExpr::FloatToBits { op }
            | SymExpr::FloatToSignedInteger { op, .. }
            | SymExpr::FloatToUnsignedInteger { op, .. }
            | SymExpr::BoolToBits { op, .. }
            | SymExpr::Extract { op, .. } => {
                *op = self.make_absolute(*op);
                self.current_id += 1;
            }
            SymExpr::Add { a, b }
            | SymExpr::Sub { a, b }
            | SymExpr::Mul { a, b }
            | SymExpr::UnsignedDiv { a, b }
            | SymExpr::SignedDiv { a, b }
            | SymExpr::UnsignedRem { a, b }
            | SymExpr::SignedRem { a, b }
            | SymExpr::ShiftLeft { a, b }
            | SymExpr::LogicalShiftRight { a, b }
            | SymExpr::ArithmeticShiftRight { a, b }
            | SymExpr::SignedLessThan { a, b }
            | SymExpr::SignedLessEqual { a, b }
            | SymExpr::SignedGreaterThan { a, b }
            | SymExpr::SignedGreaterEqual { a, b }
            | SymExpr::UnsignedLessThan { a, b }
            | SymExpr::UnsignedLessEqual { a, b }
            | SymExpr::UnsignedGreaterThan { a, b }
            | SymExpr::UnsignedGreaterEqual { a, b }
            | SymExpr::Equal { a, b }
            | SymExpr::NotEqual { a, b }
            | SymExpr::BoolAnd { a, b }
            | SymExpr::BoolOr { a, b }
            | SymExpr::BoolXor { a, b }
            | SymExpr::And { a, b }
            | SymExpr::Or { a, b }
            | SymExpr::Xor { a, b }
            | SymExpr::FloatOrdered { a, b }
            | SymExpr::FloatOrderedGreaterThan { a, b }
            | SymExpr::FloatOrderedGreaterEqual { a, b }
            | SymExpr::FloatOrderedLessThan { a, b }
            | SymExpr::FloatOrderedLessEqual { a, b }
            | SymExpr::FloatOrderedEqual { a, b }
            | SymExpr::FloatOrderedNotEqual { a, b }
            | SymExpr::FloatUnordered { a, b }
            | SymExpr::FloatUnorderedGreaterThan { a, b }
            | SymExpr::FloatUnorderedGreaterEqual { a, b }
            | SymExpr::FloatUnorderedLessThan { a, b }
            | SymExpr::FloatUnorderedLessEqual { a, b }
            | SymExpr::FloatUnorderedEqual { a, b }
            | SymExpr::FloatUnorderedNotEqual { a, b }
            | SymExpr::FloatAdd { a, b }
            | SymExpr::FloatSub { a, b }
            | SymExpr::FloatMul { a, b }
            | SymExpr::FloatDiv { a, b }
            | SymExpr::FloatRem { a, b }
            | SymExpr::Concat { a, b }
            | SymExpr::Insert {
                target: a,
                to_insert: b,
                ..
            } => {
                *a = self.make_absolute(*a);
                *b = self.make_absolute(*b);
                self.current_id += 1;
            }
            SymExpr::PathConstraint { constraint: op, .. } => {
                *op = self.make_absolute(*op);
            }
            SymExpr::ExpressionsUnreachable { exprs } => {
                for expr in exprs {
                    *expr = self.make_absolute(*expr);
                }
            }
            SymExpr::End => {
                panic!("should not pass End message to this function");
            }
        }
        SymExprRef::new(ret).unwrap()
    }
}

pub struct MessageFileWriter<W: Write> {
    id_counter: usize,
    writer: W,
    writer_start_position: u64,
    serialization_options: DefaultOptions,
}

impl<W: Write + Seek> MessageFileWriter<W> {
    pub fn from_writer(mut writer: W) -> io::Result<Self> {
        let writer_start_position = writer.stream_position()?;
        // write dummy trace length
        writer.write_all(&0u64.to_le_bytes())?;
        Ok(Self {
            id_counter: 1,
            writer,
            writer_start_position,
            serialization_options: serialization_options(),
        })
    }

    fn write_trace_size(&mut self) -> io::Result<()> {
        // calculate size of trace
        let end_pos = self.writer.stream_position()?;
        let trace_header_len = 0u64.to_le_bytes().len() as u64;
        assert!(end_pos > self.writer_start_position + trace_header_len);
        let trace_length = end_pos - self.writer_start_position - trace_header_len;

        // write trace size to beginning of trace
        self.writer
            .seek(SeekFrom::Start(self.writer_start_position))?;
        self.writer.write_all(&trace_length.to_le_bytes())?;
        // rewind to previous position
        self.writer.seek(SeekFrom::Start(end_pos))?;
        Ok(())
    }

    pub fn update_trace_header(&mut self) -> io::Result<()> {
        self.write_trace_size()?;
        Ok(())
    }

    fn make_relative(&self, expr: SymExprRef) -> SymExprRef {
        SymExprRef::new(self.id_counter - expr.get()).unwrap()
    }

    #[allow(clippy::too_many_lines)]
    pub fn write_message(&mut self, mut message: SymExpr) -> bincode::Result<SymExprRef> {
        let current_id = self.id_counter;
        match &mut message {
            SymExpr::InputByte { .. }
            | SymExpr::Integer { .. }
            | SymExpr::Integer128 { .. }
            | SymExpr::Float { .. }
            | SymExpr::NullPointer
            | SymExpr::True
            | SymExpr::False
            | SymExpr::Bool { .. } => {
                self.id_counter += 1;
            }
            SymExpr::Neg { op }
            | SymExpr::FloatAbs { op }
            | SymExpr::Not { op }
            | SymExpr::Sext { op, .. }
            | SymExpr::Zext { op, .. }
            | SymExpr::Trunc { op, .. }
            | SymExpr::IntToFloat { op, .. }
            | SymExpr::FloatToFloat { op, .. }
            | SymExpr::BitsToFloat { op, .. }
            | SymExpr::FloatToBits { op }
            | SymExpr::FloatToSignedInteger { op, .. }
            | SymExpr::FloatToUnsignedInteger { op, .. }
            | SymExpr::BoolToBits { op, .. }
            | SymExpr::Extract { op, .. } => {
                *op = self.make_relative(*op);
                self.id_counter += 1;
            }
            SymExpr::Add { a, b }
            | SymExpr::Sub { a, b }
            | SymExpr::Mul { a, b }
            | SymExpr::UnsignedDiv { a, b }
            | SymExpr::SignedDiv { a, b }
            | SymExpr::UnsignedRem { a, b }
            | SymExpr::SignedRem { a, b }
            | SymExpr::ShiftLeft { a, b }
            | SymExpr::LogicalShiftRight { a, b }
            | SymExpr::ArithmeticShiftRight { a, b }
            | SymExpr::SignedLessThan { a, b }
            | SymExpr::SignedLessEqual { a, b }
            | SymExpr::SignedGreaterThan { a, b }
            | SymExpr::SignedGreaterEqual { a, b }
            | SymExpr::UnsignedLessThan { a, b }
            | SymExpr::UnsignedLessEqual { a, b }
            | SymExpr::UnsignedGreaterThan { a, b }
            | SymExpr::UnsignedGreaterEqual { a, b }
            | SymExpr::Equal { a, b }
            | SymExpr::NotEqual { a, b }
            | SymExpr::BoolAnd { a, b }
            | SymExpr::BoolOr { a, b }
            | SymExpr::BoolXor { a, b }
            | SymExpr::And { a, b }
            | SymExpr::Or { a, b }
            | SymExpr::Xor { a, b }
            | SymExpr::FloatOrdered { a, b }
            | SymExpr::FloatOrderedGreaterThan { a, b }
            | SymExpr::FloatOrderedGreaterEqual { a, b }
            | SymExpr::FloatOrderedLessThan { a, b }
            | SymExpr::FloatOrderedLessEqual { a, b }
            | SymExpr::FloatOrderedEqual { a, b }
            | SymExpr::FloatOrderedNotEqual { a, b }
            | SymExpr::FloatUnordered { a, b }
            | SymExpr::FloatUnorderedGreaterThan { a, b }
            | SymExpr::FloatUnorderedGreaterEqual { a, b }
            | SymExpr::FloatUnorderedLessThan { a, b }
            | SymExpr::FloatUnorderedLessEqual { a, b }
            | SymExpr::FloatUnorderedEqual { a, b }
            | SymExpr::FloatUnorderedNotEqual { a, b }
            | SymExpr::FloatAdd { a, b }
            | SymExpr::FloatSub { a, b }
            | SymExpr::FloatMul { a, b }
            | SymExpr::FloatDiv { a, b }
            | SymExpr::FloatRem { a, b }
            | SymExpr::Concat { a, b }
            | SymExpr::Insert {
                target: a,
                to_insert: b,
                ..
            } => {
                *a = self.make_relative(*a);
                *b = self.make_relative(*b);
                self.id_counter += 1;
            }
            SymExpr::PathConstraint { constraint: op, .. } => {
                *op = self.make_relative(*op);
            }
            SymExpr::ExpressionsUnreachable { exprs } => {
                for expr in exprs {
                    *expr = self.make_relative(*expr);
                }
            }
            SymExpr::End => {}
        }
        self.serialization_options
            .serialize_into(&mut self.writer, &message)?;
        // for every path constraint, make sure we can later decode it in case we crash by updating the trace header
        if let SymExpr::PathConstraint { .. } = &message {
            self.write_trace_size()?;
        }
        Ok(SymExprRef::new(current_id).unwrap())
    }
}

#[cfg(test)]
mod serialization_tests {
    use std::io::Cursor;

    use super::{MessageFileReader, MessageFileWriter, SymExpr};

    /// This test intends to ensure that the serialization format can efficiently encode the required information.
    /// This is mainly useful to fail if any changes should be made in the future that (inadvertently) reduce
    /// serialization efficiency.
    #[test]
    fn efficient_serialization() {
        let mut buf = Vec::new();
        {
            let mut cursor = Cursor::new(&mut buf);
            let mut writer = MessageFileWriter::from_writer(&mut cursor).unwrap();
            let a = writer.write_message(SymExpr::True).unwrap();
            let b = writer.write_message(SymExpr::True).unwrap();
            writer.write_message(SymExpr::And { a, b }).unwrap();
            writer.update_trace_header().unwrap();
        }
        let expected_size = 8 + // the header takes 8 bytes to encode the length of the trace
                            1 + // tag to create SymExpr::True (a)
                            1 + // tag to create SymExpr::True (b)
                            1 + // tag to create SymExpr::And
                            1 + // reference to a
                            1; // reference to b
        assert_eq!(buf.len(), expected_size);
    }

    /// This test intends to verify that a trace written by [`MessageFileWriter`] can indeed be read back by
    /// [`MessageFileReader`].
    #[test]
    fn serialization_roundtrip() {
        let mut buf = Vec::new();
        {
            let mut cursor = Cursor::new(&mut buf);
            let mut writer = MessageFileWriter::from_writer(&mut cursor).unwrap();
            let a = writer.write_message(SymExpr::True).unwrap();
            let b = writer.write_message(SymExpr::True).unwrap();
            writer.write_message(SymExpr::And { a, b }).unwrap();
            writer.update_trace_header().unwrap();
        }
        let mut reader = MessageFileReader::from_length_prefixed_buffer(&buf).unwrap();
        let (first_bool_id, first_bool) = reader.next_message().unwrap().unwrap();
        assert_eq!(first_bool, SymExpr::True);
        let (second_bool_id, second_bool) = reader.next_message().unwrap().unwrap();
        assert_eq!(second_bool, SymExpr::True);
        let (_, and) = reader.next_message().unwrap().unwrap();
        assert_eq!(
            and,
            SymExpr::And {
                a: first_bool_id,
                b: second_bool_id
            }
        );
        assert!(reader.next_message().is_none());
    }
}

pub mod shared_memory {
    use std::{
        convert::TryFrom,
        io::{self, Cursor, Read},
    };

    use crate::bolts::shmem::{ShMem, ShMemCursor, ShMemProvider, StdShMemProvider};

    use super::{MessageFileReader, MessageFileWriter};

    pub const DEFAULT_ENV_NAME: &str = "SHARED_MEMORY_MESSAGES";
    pub const DEFAULT_SIZE: usize = 1024 * 1024 * 1024;

    impl<'buffer> MessageFileReader<Cursor<&'buffer [u8]>> {
        #[must_use]
        pub fn from_buffer(buffer: &'buffer [u8]) -> Self {
            Self::from_reader(Cursor::new(buffer))
        }

        pub fn from_length_prefixed_buffer(mut buffer: &'buffer [u8]) -> io::Result<Self> {
            let mut len_buf = 0u64.to_le_bytes();
            buffer.read_exact(&mut len_buf)?;
            let buffer_len = u64::from_le_bytes(len_buf);
            assert!(usize::try_from(buffer_len).is_ok());
            let buffer_len = buffer_len as usize;
            let (buffer, _) = buffer.split_at(buffer_len);
            Ok(Self::from_buffer(buffer))
        }

        #[must_use]
        pub fn get_buffer(&self) -> &[u8] {
            self.reader.get_ref()
        }
    }

    impl<T: ShMem> MessageFileWriter<ShMemCursor<T>> {
        pub fn from_shmem(shmem: T) -> io::Result<Self> {
            Self::from_writer(ShMemCursor::new(shmem))
        }
    }

    impl MessageFileWriter<ShMemCursor<<StdShMemProvider as ShMemProvider>::Mem>> {
        pub fn from_stdshmem_env_with_name(env_name: impl AsRef<str>) -> io::Result<Self> {
            Self::from_shmem(
                StdShMemProvider::new()
                    .expect("unable to initialize StdShMemProvider")
                    .existing_from_env(env_name.as_ref())
                    .expect("unable to get shared memory from env"),
            )
        }

        pub fn from_stdshmem_default_env() -> io::Result<Self> {
            Self::from_stdshmem_env_with_name(DEFAULT_ENV_NAME)
        }
    }

    pub type StdShMemMessageFileWriter =
        MessageFileWriter<ShMemCursor<<StdShMemProvider as ShMemProvider>::Mem>>;
}
