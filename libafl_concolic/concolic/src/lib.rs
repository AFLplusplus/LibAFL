use std::{
    io::{self, Cursor, Read, Write},
    num::NonZeroUsize,
};

pub use bincode::Result;
use bincode::{DefaultOptions, Options};
use serde::{Deserialize, Serialize};

pub type SymExprRef = NonZeroUsize;

fn serialization_options() -> DefaultOptions {
    DefaultOptions::new()
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    GetInputByte {
        offset: usize,
    },

    BuildInteger {
        value: u64,
        bits: u8,
    },
    BuildInteger128 {
        high: u64,
        low: u64,
    },
    BuildFloat {
        value: f64,
        is_double: bool,
    },
    BuildNullPointer,
    BuildTrue,
    BuildFalse,
    BuildBool {
        value: bool,
    },

    BuildNeg {
        op: SymExprRef,
    },
    BuildAdd {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildSub {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildMul {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildUnsignedDiv {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildSignedDiv {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildUnsignedRem {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildSignedRem {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildShiftLeft {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildLogicalShiftRight {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildArithmeticShiftRight {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildSignedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildSignedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildSignedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildSignedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildUnsignedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildUnsignedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildUnsignedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildUnsignedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildNot {
        op: SymExprRef,
    },
    BuildEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildNotEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildBoolAnd {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildBoolOr {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildBoolXor {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildAnd {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildOr {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildXor {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildFloatOrdered {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatOrderedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatOrderedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatOrderedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatOrderedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatOrderedEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatOrderedNotEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildFloatUnordered {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatUnorderedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatUnorderedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatUnorderedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatUnorderedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatUnorderedEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatUnorderedNotEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildFloatAbs {
        op: SymExprRef,
    },
    BuildFloatAdd {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatSub {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatMul {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatDiv {
        a: SymExprRef,
        b: SymExprRef,
    },
    BuildFloatRem {
        a: SymExprRef,
        b: SymExprRef,
    },

    BuildSext {
        op: SymExprRef,
        bits: u8,
    },
    BuildZext {
        op: SymExprRef,
        bits: u8,
    },
    BuildTrunc {
        op: SymExprRef,
        bits: u8,
    },
    BuildIntToFloat {
        op: SymExprRef,
        is_double: bool,
        is_signed: bool,
    },
    BuildFloatToFloat {
        op: SymExprRef,
        to_double: bool,
    },
    BuildBitsToFloat {
        op: SymExprRef,
        to_double: bool,
    },
    BuildFloatToBits {
        op: SymExprRef,
    },
    BuildFloatToSignedInteger {
        op: SymExprRef,
        bits: u8,
    },
    BuildFloatToUnsignedInteger {
        op: SymExprRef,
        bits: u8,
    },
    BuildBoolToBits {
        op: SymExprRef,
        bits: u8,
    },

    ConcatHelper {
        a: SymExprRef,
        b: SymExprRef,
    },
    ExtractHelper {
        op: SymExprRef,
        first_bit: usize,
        last_bit: usize,
    },
    BuildExtract {
        op: SymExprRef,
        offset: u64,
        length: u64,
        little_endian: bool,
    },
    BuildBswap {
        op: SymExprRef,
    },

    PushPathConstraint {
        constraint: SymExprRef,
        taken: bool,
        site_id: usize,
    },
}

pub struct MessageFileReader<R: Read> {
    reader: R,
    deserializer_config: bincode::DefaultOptions,
    current_id: usize,
}

impl<R: Read> MessageFileReader<R> {
    pub fn next_message(&mut self) -> Option<bincode::Result<(SymExprRef, Message)>> {
        match self.deserializer_config.deserialize_from(&mut self.reader) {
            Ok(mut message) => {
                let message_id = self.transform_message(&mut message);
                Some(Ok((message_id, message)))
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
        NonZeroUsize::new(self.current_id - expr.get()).unwrap()
    }

    fn transform_message(&mut self, message: &mut Message) -> SymExprRef {
        let ret = self.current_id;
        match message {
            Message::GetInputByte { .. }
            | Message::BuildInteger { .. }
            | Message::BuildInteger128 { .. }
            | Message::BuildFloat { .. }
            | Message::BuildNullPointer
            | Message::BuildTrue
            | Message::BuildFalse
            | Message::BuildBool { .. } => {
                self.current_id += 1;
            }
            Message::BuildNeg { op }
            | Message::BuildFloatAbs { op }
            | Message::BuildNot { op }
            | Message::BuildSext { op, .. }
            | Message::BuildZext { op, .. }
            | Message::BuildTrunc { op, .. }
            | Message::BuildIntToFloat { op, .. }
            | Message::BuildFloatToFloat { op, .. }
            | Message::BuildBitsToFloat { op, .. }
            | Message::BuildFloatToBits { op }
            | Message::BuildFloatToSignedInteger { op, .. }
            | Message::BuildFloatToUnsignedInteger { op, .. }
            | Message::BuildBoolToBits { op, .. }
            | Message::ExtractHelper { op, .. }
            | Message::BuildExtract { op, .. }
            | Message::BuildBswap { op } => {
                *op = self.make_absolute(*op);
                self.current_id += 1;
            }
            Message::BuildAdd { a, b }
            | Message::BuildSub { a, b }
            | Message::BuildMul { a, b }
            | Message::BuildUnsignedDiv { a, b }
            | Message::BuildSignedDiv { a, b }
            | Message::BuildUnsignedRem { a, b }
            | Message::BuildSignedRem { a, b }
            | Message::BuildShiftLeft { a, b }
            | Message::BuildLogicalShiftRight { a, b }
            | Message::BuildArithmeticShiftRight { a, b }
            | Message::BuildSignedLessThan { a, b }
            | Message::BuildSignedLessEqual { a, b }
            | Message::BuildSignedGreaterThan { a, b }
            | Message::BuildSignedGreaterEqual { a, b }
            | Message::BuildUnsignedLessThan { a, b }
            | Message::BuildUnsignedLessEqual { a, b }
            | Message::BuildUnsignedGreaterThan { a, b }
            | Message::BuildUnsignedGreaterEqual { a, b }
            | Message::BuildEqual { a, b }
            | Message::BuildNotEqual { a, b }
            | Message::BuildBoolAnd { a, b }
            | Message::BuildBoolOr { a, b }
            | Message::BuildBoolXor { a, b }
            | Message::BuildAnd { a, b }
            | Message::BuildOr { a, b }
            | Message::BuildXor { a, b }
            | Message::BuildFloatOrdered { a, b }
            | Message::BuildFloatOrderedGreaterThan { a, b }
            | Message::BuildFloatOrderedGreaterEqual { a, b }
            | Message::BuildFloatOrderedLessThan { a, b }
            | Message::BuildFloatOrderedLessEqual { a, b }
            | Message::BuildFloatOrderedEqual { a, b }
            | Message::BuildFloatOrderedNotEqual { a, b }
            | Message::BuildFloatUnordered { a, b }
            | Message::BuildFloatUnorderedGreaterThan { a, b }
            | Message::BuildFloatUnorderedGreaterEqual { a, b }
            | Message::BuildFloatUnorderedLessThan { a, b }
            | Message::BuildFloatUnorderedLessEqual { a, b }
            | Message::BuildFloatUnorderedEqual { a, b }
            | Message::BuildFloatUnorderedNotEqual { a, b }
            | Message::BuildFloatAdd { a, b }
            | Message::BuildFloatSub { a, b }
            | Message::BuildFloatMul { a, b }
            | Message::BuildFloatDiv { a, b }
            | Message::BuildFloatRem { a, b }
            | Message::ConcatHelper { a, b } => {
                *a = self.make_absolute(*a);
                *b = self.make_absolute(*b);
                self.current_id += 1;
            }
            Message::PushPathConstraint { constraint: op, .. } => {
                *op = self.make_absolute(*op);
            }
        }
        NonZeroUsize::new(ret).unwrap()
    }
}

impl<'buffer> MessageFileReader<Cursor<&'buffer [u8]>> {
    pub fn new_from_buffer(buffer: &'buffer [u8]) -> Self {
        let reader = Cursor::new(buffer);
        Self {
            reader,
            deserializer_config: serialization_options(),
            current_id: 1,
        }
    }
}

pub struct MessageFileWriter<W: Write> {
    id_counter: usize,
    writer: W,
    serialization_options: DefaultOptions,
}

impl<W: Write> MessageFileWriter<W> {
    pub fn new_from_writer(writer: W) -> Self {
        Self {
            writer,
            id_counter: 1,
            serialization_options: serialization_options(),
        }
    }

    fn make_relative(&self, expr: SymExprRef) -> SymExprRef {
        NonZeroUsize::new(self.id_counter - expr.get()).unwrap()
    }

    pub fn write_message(&mut self, mut message: Message) -> SymExprRef {
        let current_id = self.id_counter;
        match &mut message {
            Message::GetInputByte { .. }
            | Message::BuildInteger { .. }
            | Message::BuildInteger128 { .. }
            | Message::BuildFloat { .. }
            | Message::BuildNullPointer
            | Message::BuildTrue
            | Message::BuildFalse
            | Message::BuildBool { .. } => {
                self.id_counter += 1;
            }
            Message::BuildNeg { op }
            | Message::BuildFloatAbs { op }
            | Message::BuildNot { op }
            | Message::BuildSext { op, .. }
            | Message::BuildZext { op, .. }
            | Message::BuildTrunc { op, .. }
            | Message::BuildIntToFloat { op, .. }
            | Message::BuildFloatToFloat { op, .. }
            | Message::BuildBitsToFloat { op, .. }
            | Message::BuildFloatToBits { op }
            | Message::BuildFloatToSignedInteger { op, .. }
            | Message::BuildFloatToUnsignedInteger { op, .. }
            | Message::BuildBoolToBits { op, .. }
            | Message::ExtractHelper { op, .. }
            | Message::BuildExtract { op, .. }
            | Message::BuildBswap { op } => {
                *op = self.make_relative(*op);
                self.id_counter += 1;
            }
            Message::BuildAdd { a, b }
            | Message::BuildSub { a, b }
            | Message::BuildMul { a, b }
            | Message::BuildUnsignedDiv { a, b }
            | Message::BuildSignedDiv { a, b }
            | Message::BuildUnsignedRem { a, b }
            | Message::BuildSignedRem { a, b }
            | Message::BuildShiftLeft { a, b }
            | Message::BuildLogicalShiftRight { a, b }
            | Message::BuildArithmeticShiftRight { a, b }
            | Message::BuildSignedLessThan { a, b }
            | Message::BuildSignedLessEqual { a, b }
            | Message::BuildSignedGreaterThan { a, b }
            | Message::BuildSignedGreaterEqual { a, b }
            | Message::BuildUnsignedLessThan { a, b }
            | Message::BuildUnsignedLessEqual { a, b }
            | Message::BuildUnsignedGreaterThan { a, b }
            | Message::BuildUnsignedGreaterEqual { a, b }
            | Message::BuildEqual { a, b }
            | Message::BuildNotEqual { a, b }
            | Message::BuildBoolAnd { a, b }
            | Message::BuildBoolOr { a, b }
            | Message::BuildBoolXor { a, b }
            | Message::BuildAnd { a, b }
            | Message::BuildOr { a, b }
            | Message::BuildXor { a, b }
            | Message::BuildFloatOrdered { a, b }
            | Message::BuildFloatOrderedGreaterThan { a, b }
            | Message::BuildFloatOrderedGreaterEqual { a, b }
            | Message::BuildFloatOrderedLessThan { a, b }
            | Message::BuildFloatOrderedLessEqual { a, b }
            | Message::BuildFloatOrderedEqual { a, b }
            | Message::BuildFloatOrderedNotEqual { a, b }
            | Message::BuildFloatUnordered { a, b }
            | Message::BuildFloatUnorderedGreaterThan { a, b }
            | Message::BuildFloatUnorderedGreaterEqual { a, b }
            | Message::BuildFloatUnorderedLessThan { a, b }
            | Message::BuildFloatUnorderedLessEqual { a, b }
            | Message::BuildFloatUnorderedEqual { a, b }
            | Message::BuildFloatUnorderedNotEqual { a, b }
            | Message::BuildFloatAdd { a, b }
            | Message::BuildFloatSub { a, b }
            | Message::BuildFloatMul { a, b }
            | Message::BuildFloatDiv { a, b }
            | Message::BuildFloatRem { a, b }
            | Message::ConcatHelper { a, b } => {
                *a = self.make_relative(*a);
                *b = self.make_relative(*b);
                self.id_counter += 1;
            }
            Message::PushPathConstraint { constraint: op, .. } => {
                *op = self.make_relative(*op);
            }
        }
        self.serialization_options
            .serialize_into(&mut self.writer, &message)
            .expect("unable to serialize message");
        NonZeroUsize::new(current_id).unwrap()
    }
}

impl<T: ShMem> MessageFileWriter<ShMemCursor<T>> {
    pub fn new_from_shmem(shmem: T) -> Self {
        Self::new_from_writer(ShMemCursor::from_shmem(shmem))
    }
}

impl MessageFileWriter<ShMemCursor<<StdShMemProvider as ShMemProvider>::Mem>> {
    pub fn new_from_stdshmem_env(env_name: impl AsRef<str>) -> Self {
        Self::new_from_shmem(
            StdShMemProvider::new()
                .expect("unable to initialize StdShMemProvider")
                .existing_from_env(env_name.as_ref())
                .expect("unable to get shared memory from env"),
        )
    }
}

use libafl::bolts::shmem::{ShMem, ShMemProvider, ShMemCursor, StdShMemProvider};

pub type StdShMemMessageFileWriter =
    MessageFileWriter<ShMemCursor<<StdShMemProvider as ShMemProvider>::Mem>>;
