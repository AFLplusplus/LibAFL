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
            SymExpr::GetInputByte { .. }
            | SymExpr::BuildInteger { .. }
            | SymExpr::BuildInteger128 { .. }
            | SymExpr::BuildFloat { .. }
            | SymExpr::BuildNullPointer
            | SymExpr::BuildTrue
            | SymExpr::BuildFalse
            | SymExpr::BuildBool { .. } => {
                self.current_id += 1;
            }
            SymExpr::BuildNeg { op }
            | SymExpr::BuildFloatAbs { op }
            | SymExpr::BuildNot { op }
            | SymExpr::BuildSext { op, .. }
            | SymExpr::BuildZext { op, .. }
            | SymExpr::BuildTrunc { op, .. }
            | SymExpr::BuildIntToFloat { op, .. }
            | SymExpr::BuildFloatToFloat { op, .. }
            | SymExpr::BuildBitsToFloat { op, .. }
            | SymExpr::BuildFloatToBits { op }
            | SymExpr::BuildFloatToSignedInteger { op, .. }
            | SymExpr::BuildFloatToUnsignedInteger { op, .. }
            | SymExpr::BuildBoolToBits { op, .. }
            | SymExpr::ExtractHelper { op, .. }
            | SymExpr::BuildExtract { op, .. }
            | SymExpr::BuildBswap { op } => {
                *op = self.make_absolute(*op);
                self.current_id += 1;
            }
            SymExpr::BuildAdd { a, b }
            | SymExpr::BuildSub { a, b }
            | SymExpr::BuildMul { a, b }
            | SymExpr::BuildUnsignedDiv { a, b }
            | SymExpr::BuildSignedDiv { a, b }
            | SymExpr::BuildUnsignedRem { a, b }
            | SymExpr::BuildSignedRem { a, b }
            | SymExpr::BuildShiftLeft { a, b }
            | SymExpr::BuildLogicalShiftRight { a, b }
            | SymExpr::BuildArithmeticShiftRight { a, b }
            | SymExpr::BuildSignedLessThan { a, b }
            | SymExpr::BuildSignedLessEqual { a, b }
            | SymExpr::BuildSignedGreaterThan { a, b }
            | SymExpr::BuildSignedGreaterEqual { a, b }
            | SymExpr::BuildUnsignedLessThan { a, b }
            | SymExpr::BuildUnsignedLessEqual { a, b }
            | SymExpr::BuildUnsignedGreaterThan { a, b }
            | SymExpr::BuildUnsignedGreaterEqual { a, b }
            | SymExpr::BuildEqual { a, b }
            | SymExpr::BuildNotEqual { a, b }
            | SymExpr::BuildBoolAnd { a, b }
            | SymExpr::BuildBoolOr { a, b }
            | SymExpr::BuildBoolXor { a, b }
            | SymExpr::BuildAnd { a, b }
            | SymExpr::BuildOr { a, b }
            | SymExpr::BuildXor { a, b }
            | SymExpr::BuildFloatOrdered { a, b }
            | SymExpr::BuildFloatOrderedGreaterThan { a, b }
            | SymExpr::BuildFloatOrderedGreaterEqual { a, b }
            | SymExpr::BuildFloatOrderedLessThan { a, b }
            | SymExpr::BuildFloatOrderedLessEqual { a, b }
            | SymExpr::BuildFloatOrderedEqual { a, b }
            | SymExpr::BuildFloatOrderedNotEqual { a, b }
            | SymExpr::BuildFloatUnordered { a, b }
            | SymExpr::BuildFloatUnorderedGreaterThan { a, b }
            | SymExpr::BuildFloatUnorderedGreaterEqual { a, b }
            | SymExpr::BuildFloatUnorderedLessThan { a, b }
            | SymExpr::BuildFloatUnorderedLessEqual { a, b }
            | SymExpr::BuildFloatUnorderedEqual { a, b }
            | SymExpr::BuildFloatUnorderedNotEqual { a, b }
            | SymExpr::BuildFloatAdd { a, b }
            | SymExpr::BuildFloatSub { a, b }
            | SymExpr::BuildFloatMul { a, b }
            | SymExpr::BuildFloatDiv { a, b }
            | SymExpr::BuildFloatRem { a, b }
            | SymExpr::ConcatHelper { a, b }
            | SymExpr::BuildInsert {
                target: a,
                to_insert: b,
                ..
            } => {
                *a = self.make_absolute(*a);
                *b = self.make_absolute(*b);
                self.current_id += 1;
            }
            SymExpr::PushPathConstraint { constraint: op, .. } => {
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

    pub fn end(&mut self) -> io::Result<()> {
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
            SymExpr::GetInputByte { .. }
            | SymExpr::BuildInteger { .. }
            | SymExpr::BuildInteger128 { .. }
            | SymExpr::BuildFloat { .. }
            | SymExpr::BuildNullPointer
            | SymExpr::BuildTrue
            | SymExpr::BuildFalse
            | SymExpr::BuildBool { .. } => {
                self.id_counter += 1;
            }
            SymExpr::BuildNeg { op }
            | SymExpr::BuildFloatAbs { op }
            | SymExpr::BuildNot { op }
            | SymExpr::BuildSext { op, .. }
            | SymExpr::BuildZext { op, .. }
            | SymExpr::BuildTrunc { op, .. }
            | SymExpr::BuildIntToFloat { op, .. }
            | SymExpr::BuildFloatToFloat { op, .. }
            | SymExpr::BuildBitsToFloat { op, .. }
            | SymExpr::BuildFloatToBits { op }
            | SymExpr::BuildFloatToSignedInteger { op, .. }
            | SymExpr::BuildFloatToUnsignedInteger { op, .. }
            | SymExpr::BuildBoolToBits { op, .. }
            | SymExpr::ExtractHelper { op, .. }
            | SymExpr::BuildExtract { op, .. }
            | SymExpr::BuildBswap { op } => {
                *op = self.make_relative(*op);
                self.id_counter += 1;
            }
            SymExpr::BuildAdd { a, b }
            | SymExpr::BuildSub { a, b }
            | SymExpr::BuildMul { a, b }
            | SymExpr::BuildUnsignedDiv { a, b }
            | SymExpr::BuildSignedDiv { a, b }
            | SymExpr::BuildUnsignedRem { a, b }
            | SymExpr::BuildSignedRem { a, b }
            | SymExpr::BuildShiftLeft { a, b }
            | SymExpr::BuildLogicalShiftRight { a, b }
            | SymExpr::BuildArithmeticShiftRight { a, b }
            | SymExpr::BuildSignedLessThan { a, b }
            | SymExpr::BuildSignedLessEqual { a, b }
            | SymExpr::BuildSignedGreaterThan { a, b }
            | SymExpr::BuildSignedGreaterEqual { a, b }
            | SymExpr::BuildUnsignedLessThan { a, b }
            | SymExpr::BuildUnsignedLessEqual { a, b }
            | SymExpr::BuildUnsignedGreaterThan { a, b }
            | SymExpr::BuildUnsignedGreaterEqual { a, b }
            | SymExpr::BuildEqual { a, b }
            | SymExpr::BuildNotEqual { a, b }
            | SymExpr::BuildBoolAnd { a, b }
            | SymExpr::BuildBoolOr { a, b }
            | SymExpr::BuildBoolXor { a, b }
            | SymExpr::BuildAnd { a, b }
            | SymExpr::BuildOr { a, b }
            | SymExpr::BuildXor { a, b }
            | SymExpr::BuildFloatOrdered { a, b }
            | SymExpr::BuildFloatOrderedGreaterThan { a, b }
            | SymExpr::BuildFloatOrderedGreaterEqual { a, b }
            | SymExpr::BuildFloatOrderedLessThan { a, b }
            | SymExpr::BuildFloatOrderedLessEqual { a, b }
            | SymExpr::BuildFloatOrderedEqual { a, b }
            | SymExpr::BuildFloatOrderedNotEqual { a, b }
            | SymExpr::BuildFloatUnordered { a, b }
            | SymExpr::BuildFloatUnorderedGreaterThan { a, b }
            | SymExpr::BuildFloatUnorderedGreaterEqual { a, b }
            | SymExpr::BuildFloatUnorderedLessThan { a, b }
            | SymExpr::BuildFloatUnorderedLessEqual { a, b }
            | SymExpr::BuildFloatUnorderedEqual { a, b }
            | SymExpr::BuildFloatUnorderedNotEqual { a, b }
            | SymExpr::BuildFloatAdd { a, b }
            | SymExpr::BuildFloatSub { a, b }
            | SymExpr::BuildFloatMul { a, b }
            | SymExpr::BuildFloatDiv { a, b }
            | SymExpr::BuildFloatRem { a, b }
            | SymExpr::ConcatHelper { a, b }
            | SymExpr::BuildInsert {
                target: a,
                to_insert: b,
                ..
            } => {
                *a = self.make_relative(*a);
                *b = self.make_relative(*b);
                self.id_counter += 1;
            }
            SymExpr::PushPathConstraint { constraint: op, .. } => {
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
        if let SymExpr::PushPathConstraint { .. } = &message {
            self.write_trace_size()?;
        }
        Ok(SymExprRef::new(current_id).unwrap())
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
