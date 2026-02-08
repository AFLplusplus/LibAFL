//! # Concolic Tracing Serialization Format
//!
//! ## Design Goals
//! * The serialization format for concolic tracing was developed with the goal of being space and time efficient.
//! * Additionally, it should be easy to maintain and extend.
//! * It does not have to be compatible with other programming languages.
//! * It should be resilient to crashes. Since we are fuzzing, we are expecting the traced program to crash at some
//!   point.
//!
//! The format as implemented fulfils these design goals.
//! Specifically:
//! * it requires only constant memory space for serialization, which allows for tracing complex and/or
//!   long-running programs.
//! * the trace itself requires little space. A typical binary operation (such as an add) typically takes just a few bytes.
//! * it easy to encode. There is no translation between the interface of the runtime itself and the trace it generates.
//! * it is similarly easy to decode and can be easily translated into an in-memory AST without overhead, because
//!   expressions are decoded from leaf to root instead of root to leaf.
//! * At its core, it is just [`SymExpr`]s, which can be added to, modified and removed from with ease. The
//!   definitions are automatically shared between the runtime and the consuming program, since both depend on the same
//!   `LibAFL`.
//!
//! ## Techniques
//! The serialization format applies multiple techniques to achieve its goals.
//! * It uses postcard for efficient binary serialization. Crucially, postcard uses variable length integer encoding,
//!   allowing it encode small integers use fewer bytes.
//! * References to previous expressions are stored relative to the current expressions id. The vast majority of
//!   expressions refer to other expressions that were defined close to their use. Therefore, encoding relative references
//!   keeps references small. Therefore, they make optimal use of postcard's variable length integer encoding.
//! * Ids of expressions ([`SymExprRef`]s) are implicitly derived by their position in the message stream. Effectively,
//!   a counter is used to identify expressions.
//! * The current length of the trace in bytes in serialized in a fixed format at the beginning of the trace.
//!   This length is updated regularly when the trace is in a consistent state. This allows the reader to avoid reading
//!   malformed data if the traced process crashed.
//!
//! ## Example
//! The expression `SymExpr::BoolAnd { a: SymExpr::True, b: SymExpr::False }` would be encoded as:
//! 1. 1 byte to identify `SymExpr::True` (a)
//! 2. 1 byte to identify `SymExpr::False` (b)
//! 3. 1 byte to identify `SymExpr::BoolAnd`
//! 4. 1 byte to reference a
//! 5. 1 byte to reference b
//!
//! ... making for a total of 5 bytes.

use core::fmt::{self, Debug, Formatter};
use std::io::{self, Seek, SeekFrom, Write};

use postcard::Error as PostcardError;

use super::{SymExpr, SymExprRef};

/// A `MessageFileReader` reads a stream of [`SymExpr`] and their corresponding [`SymExprRef`]s from a byte buffer.
pub struct MessageFileReader<'a> {
    buffer: &'a [u8],
    current_id: usize,
}

impl Debug for MessageFileReader<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "MessageFileReader {{ current_id: {}, remaining: {} bytes }}",
            self.current_id,
            self.buffer.len()
        )
    }
}

impl<'a> MessageFileReader<'a> {
    /// Construct from the given buffer.
    #[must_use]
    pub fn from_buffer(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            current_id: 1,
        }
    }

    /// Parse the next message out of the buffer.
    /// [`Option::None`] is returned once the buffer is depleted.
    /// Serialization errors are passed to the caller as [`PostcardError`].
    /// Finally, the returned tuple contains the message itself as a [`SymExpr`] and the [`SymExprRef`] associated
    /// with this message.
    /// The `SymExprRef` may be used by following messages to refer back to this message.
    pub fn next_message(&mut self) -> Option<Result<(SymExprRef, SymExpr), PostcardError>> {
        if self.buffer.is_empty() {
            return None;
        }

        // Use postcard's take_from_bytes which deserializes and returns remaining bytes
        match postcard::take_from_bytes::<SymExpr>(self.buffer) {
            Ok((mut message, remaining)) => {
                self.buffer = remaining;
                let message_id = self.transform_message(&mut message);
                Some(Ok((message_id, message)))
            }
            Err(e) => Some(Err(e)),
        }
    }

    /// Makes the given `SymExprRef` absolute accoring to the `current_id` counter.
    /// See [`MessageFileWriter::make_relative`] for the inverse function.
    fn make_absolute(&self, expr: SymExprRef) -> SymExprRef {
        SymExprRef::new(self.current_id - expr.get()).unwrap()
    }

    /// This transforms the given message from it's serialized form into its in-memory form, making relative references
    /// absolute and counting the `SymExprRef`s.
    #[expect(clippy::too_many_lines)]
    fn transform_message(&mut self, message: &mut SymExpr) -> SymExprRef {
        let ret = self.current_id;
        match message {
            SymExpr::InputByte { .. }
            | SymExpr::Integer { .. }
            | SymExpr::Integer128 { .. }
            | SymExpr::IntegerFromBuffer { .. }
            | SymExpr::Float { .. }
            | SymExpr::NullPointer
            | SymExpr::True
            | SymExpr::False
            | SymExpr::Bool { .. } => {
                self.current_id += 1;
            }
            SymExpr::Neg { op }
            | SymExpr::FloatAbs { op }
            | SymExpr::FloatNeg { op }
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
            | SymExpr::BoolToBit { op, .. }
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
            SymExpr::Call { .. } | SymExpr::Return { .. } | SymExpr::BasicBlock { .. } => {}
            SymExpr::Ite { cond, a, b } => {
                *cond = self.make_absolute(*cond);
                *a = self.make_absolute(*a);
                *b = self.make_absolute(*b);
                self.current_id += 1;
            }
        }
        SymExprRef::new(ret).unwrap()
    }
}

/// A `MessageFileWriter` writes a stream of [`SymExpr`] to any [`Write`]. For each written expression, it returns
/// a [`SymExprRef`] which should be used to refer back to it.
pub struct MessageFileWriter<W> {
    id_counter: usize,
    writer: W,
    writer_start_position: u64,
}

impl<W> Debug for MessageFileWriter<W>
where
    W: Write,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageFileWriter")
            .field("id_counter", &self.id_counter)
            .field("writer_start_position", &self.writer_start_position)
            .finish_non_exhaustive()
    }
}

impl<W: Write + Seek> MessageFileWriter<W> {
    /// Create a `MessageFileWriter` from the given [`Write`].
    pub fn from_writer(mut writer: W) -> io::Result<Self> {
        let writer_start_position = writer.stream_position()?;
        // write preliminary trace length
        writer.write_all(&0_u64.to_le_bytes())?;
        Ok(Self {
            id_counter: 1,
            writer,
            writer_start_position,
        })
    }

    fn write_trace_size(&mut self) -> io::Result<()> {
        // calculate size of trace
        let end_pos = self.writer.stream_position()?;
        let trace_header_len = 0_u64.to_le_bytes().len() as u64;
        assert!(
            end_pos >= self.writer_start_position + trace_header_len,
            "our end position can not be before our start position"
        );
        let trace_length = end_pos - self.writer_start_position - trace_header_len;

        // write trace size to beginning of trace
        self.writer
            .seek(SeekFrom::Start(self.writer_start_position))?;
        self.writer.write_all(&trace_length.to_le_bytes())?;
        // rewind to previous position
        self.writer.seek(SeekFrom::Start(end_pos))?;
        Ok(())
    }

    /// Updates the trace header which stores the total length of the trace in bytes.
    pub fn update_trace_header(&mut self) -> io::Result<()> {
        self.write_trace_size()?;
        Ok(())
    }

    fn make_relative(&self, expr: SymExprRef) -> SymExprRef {
        SymExprRef::new(self.id_counter - expr.get()).unwrap()
    }

    /// Writes a message to the stream and returns the [`SymExprRef`] that should be used to refer back to this message.
    /// May error when the underlying `Write` errors or when there is a serialization error.
    #[expect(clippy::too_many_lines)]
    pub fn write_message(&mut self, mut message: SymExpr) -> Result<SymExprRef, PostcardError> {
        let current_id = self.id_counter;
        match &mut message {
            SymExpr::InputByte { .. }
            | SymExpr::Integer { .. }
            | SymExpr::Integer128 { .. }
            | SymExpr::IntegerFromBuffer { .. }
            | SymExpr::Float { .. }
            | SymExpr::NullPointer
            | SymExpr::True
            | SymExpr::False
            | SymExpr::Bool { .. } => {
                self.id_counter += 1;
            }
            SymExpr::Neg { op }
            | SymExpr::FloatAbs { op }
            | SymExpr::FloatNeg { op }
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
            | SymExpr::BoolToBit { op, .. }
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
            SymExpr::Call { .. } | SymExpr::Return { .. } | SymExpr::BasicBlock { .. } => {}
            SymExpr::Ite { cond, a, b } => {
                *cond = self.make_relative(*cond);
                *a = self.make_relative(*a);
                *b = self.make_relative(*b);
            }
        }

        // Serialize and write directly with postcard
        let serialized = postcard::to_allocvec(&message)?;
        self.writer
            .write_all(&serialized)
            .map_err(|_| PostcardError::SerializeBufferFull)?;

        // for every path constraint, make sure we can later decode it in case we crash by updating the trace header
        if let SymExpr::PathConstraint { .. } = &message {
            self.write_trace_size()
                .map_err(|_| PostcardError::SerializeBufferFull)?;
        }
        Ok(SymExprRef::new(current_id).unwrap())
    }
}

use libafl_bolts::shmem::{ShMem, ShMemCursor, ShMemProvider, StdShMem, StdShMemProvider};

/// The default environment variable name to use for the shared memory used by the concolic tracing
pub const DEFAULT_ENV_NAME: &str = "SHARED_MEMORY_MESSAGES";

/// The default shared memory size used by the concolic tracing.
///
/// This amounts to 1GiB of memory, which is considered to be enough for any reasonable trace. It is also assumed
/// that the memory will not be physically mapped until accessed, alleviating resource concerns.
pub const DEFAULT_SIZE: usize = 1024 * 1024 * 1024;

impl<'a> MessageFileReader<'a> {
    /// Creates a new `MessageFileReader` from the given buffer, expecting the contained trace to be prefixed by the
    /// trace length (as generated by the [`MessageFileWriter`]).
    pub fn from_length_prefixed_buffer(buffer: &'a [u8]) -> io::Result<Self> {
        if buffer.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Buffer too small for trace header",
            ));
        }
        let len_bytes: [u8; 8] = buffer[0..8].try_into().unwrap();
        let trace_len = u64::from_le_bytes(len_bytes) as usize;

        if buffer.len() < 8 + trace_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Buffer smaller than trace length",
            ));
        }

        let trace_buffer = &buffer[8..8 + trace_len];
        Ok(Self::from_buffer(trace_buffer))
    }

    /// Gets the remaining buffer
    #[must_use]
    pub fn get_buffer(&self) -> &[u8] {
        self.buffer
    }
}

impl<SHM> MessageFileWriter<ShMemCursor<SHM>>
where
    SHM: ShMem,
{
    /// Creates a new `MessageFileWriter` from the given [`ShMemCursor`].
    pub fn from_shmem(shmem: SHM) -> io::Result<Self> {
        Self::from_writer(ShMemCursor::new(shmem))
    }
}

impl MessageFileWriter<ShMemCursor<StdShMem>> {
    /// Creates a new `MessageFileWriter` by reading a [`ShMem`] from the given environment variable.
    pub fn from_stdshmem_env_with_name(env_name: impl AsRef<str>) -> io::Result<Self> {
        Self::from_shmem(
            StdShMemProvider::new()
                .expect("unable to initialize StdShMemProvider")
                .existing_from_env(env_name.as_ref())
                .expect("unable to get shared memory from env"),
        )
    }

    /// Creates a new `MessageFileWriter` by reading a [`ShMem`] using [`DEFAULT_ENV_NAME`].
    pub fn from_stdshmem_default_env() -> io::Result<Self> {
        Self::from_stdshmem_env_with_name(DEFAULT_ENV_NAME)
    }
}

/// A writer that will write messages to a shared memory buffer.
pub type StdShMemMessageFileWriter<SHM> = MessageFileWriter<ShMemCursor<SHM>>;

#[cfg(test)]
mod serialization_tests {
    use alloc::vec::Vec;
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
