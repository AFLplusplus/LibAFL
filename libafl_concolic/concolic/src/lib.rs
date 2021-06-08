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
        use Message::*;
        let ret = self.current_id;
        match message {
            GetInputByte { .. }
            | BuildInteger { .. }
            | BuildInteger128 { .. }
            | BuildFloat { .. }
            | BuildNullPointer
            | BuildTrue
            | BuildFalse
            | BuildBool { .. } => {
                self.current_id += 1;
            }
            BuildNeg { op }
            | BuildFloatAbs { op }
            | BuildNot { op }
            | BuildSext { op, .. }
            | BuildZext { op, .. }
            | BuildTrunc { op, .. }
            | BuildIntToFloat { op, .. }
            | BuildFloatToFloat { op, .. }
            | BuildBitsToFloat { op, .. }
            | BuildFloatToBits { op }
            | BuildFloatToSignedInteger { op, .. }
            | BuildFloatToUnsignedInteger { op, .. }
            | BuildBoolToBits { op, .. }
            | ExtractHelper { op, .. }
            | BuildExtract { op, .. }
            | BuildBswap { op } => {
                *op = self.make_absolute(*op);
                self.current_id += 1;
            }
            BuildAdd { a, b }
            | BuildSub { a, b }
            | BuildMul { a, b }
            | BuildUnsignedDiv { a, b }
            | BuildSignedDiv { a, b }
            | BuildUnsignedRem { a, b }
            | BuildSignedRem { a, b }
            | BuildShiftLeft { a, b }
            | BuildLogicalShiftRight { a, b }
            | BuildArithmeticShiftRight { a, b }
            | BuildSignedLessThan { a, b }
            | BuildSignedLessEqual { a, b }
            | BuildSignedGreaterThan { a, b }
            | BuildSignedGreaterEqual { a, b }
            | BuildUnsignedLessThan { a, b }
            | BuildUnsignedLessEqual { a, b }
            | BuildUnsignedGreaterThan { a, b }
            | BuildUnsignedGreaterEqual { a, b }
            | BuildEqual { a, b }
            | BuildNotEqual { a, b }
            | BuildBoolAnd { a, b }
            | BuildBoolOr { a, b }
            | BuildBoolXor { a, b }
            | BuildAnd { a, b }
            | BuildOr { a, b }
            | BuildXor { a, b }
            | BuildFloatOrdered { a, b }
            | BuildFloatOrderedGreaterThan { a, b }
            | BuildFloatOrderedGreaterEqual { a, b }
            | BuildFloatOrderedLessThan { a, b }
            | BuildFloatOrderedLessEqual { a, b }
            | BuildFloatOrderedEqual { a, b }
            | BuildFloatOrderedNotEqual { a, b }
            | BuildFloatUnordered { a, b }
            | BuildFloatUnorderedGreaterThan { a, b }
            | BuildFloatUnorderedGreaterEqual { a, b }
            | BuildFloatUnorderedLessThan { a, b }
            | BuildFloatUnorderedLessEqual { a, b }
            | BuildFloatUnorderedEqual { a, b }
            | BuildFloatUnorderedNotEqual { a, b }
            | BuildFloatAdd { a, b }
            | BuildFloatSub { a, b }
            | BuildFloatMul { a, b }
            | BuildFloatDiv { a, b }
            | BuildFloatRem { a, b }
            | ConcatHelper { a, b } => {
                *a = self.make_absolute(*a);
                *b = self.make_absolute(*b);
                self.current_id += 1;
            }
            PushPathConstraint { constraint: op, .. } => {
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
        use Message::*;
        let current_id = self.id_counter;
        match &mut message {
            GetInputByte { .. }
            | BuildInteger { .. }
            | BuildInteger128 { .. }
            | BuildFloat { .. }
            | BuildNullPointer
            | BuildTrue
            | BuildFalse
            | BuildBool { .. } => {
                self.id_counter += 1;
            }
            BuildNeg { op }
            | BuildFloatAbs { op }
            | BuildNot { op }
            | BuildSext { op, .. }
            | BuildZext { op, .. }
            | BuildTrunc { op, .. }
            | BuildIntToFloat { op, .. }
            | BuildFloatToFloat { op, .. }
            | BuildBitsToFloat { op, .. }
            | BuildFloatToBits { op }
            | BuildFloatToSignedInteger { op, .. }
            | BuildFloatToUnsignedInteger { op, .. }
            | BuildBoolToBits { op, .. }
            | ExtractHelper { op, .. }
            | BuildExtract { op, .. }
            | BuildBswap { op } => {
                *op = self.make_relative(*op);
                self.id_counter += 1;
            }
            BuildAdd { a, b }
            | BuildSub { a, b }
            | BuildMul { a, b }
            | BuildUnsignedDiv { a, b }
            | BuildSignedDiv { a, b }
            | BuildUnsignedRem { a, b }
            | BuildSignedRem { a, b }
            | BuildShiftLeft { a, b }
            | BuildLogicalShiftRight { a, b }
            | BuildArithmeticShiftRight { a, b }
            | BuildSignedLessThan { a, b }
            | BuildSignedLessEqual { a, b }
            | BuildSignedGreaterThan { a, b }
            | BuildSignedGreaterEqual { a, b }
            | BuildUnsignedLessThan { a, b }
            | BuildUnsignedLessEqual { a, b }
            | BuildUnsignedGreaterThan { a, b }
            | BuildUnsignedGreaterEqual { a, b }
            | BuildEqual { a, b }
            | BuildNotEqual { a, b }
            | BuildBoolAnd { a, b }
            | BuildBoolOr { a, b }
            | BuildBoolXor { a, b }
            | BuildAnd { a, b }
            | BuildOr { a, b }
            | BuildXor { a, b }
            | BuildFloatOrdered { a, b }
            | BuildFloatOrderedGreaterThan { a, b }
            | BuildFloatOrderedGreaterEqual { a, b }
            | BuildFloatOrderedLessThan { a, b }
            | BuildFloatOrderedLessEqual { a, b }
            | BuildFloatOrderedEqual { a, b }
            | BuildFloatOrderedNotEqual { a, b }
            | BuildFloatUnordered { a, b }
            | BuildFloatUnorderedGreaterThan { a, b }
            | BuildFloatUnorderedGreaterEqual { a, b }
            | BuildFloatUnorderedLessThan { a, b }
            | BuildFloatUnorderedLessEqual { a, b }
            | BuildFloatUnorderedEqual { a, b }
            | BuildFloatUnorderedNotEqual { a, b }
            | BuildFloatAdd { a, b }
            | BuildFloatSub { a, b }
            | BuildFloatMul { a, b }
            | BuildFloatDiv { a, b }
            | BuildFloatRem { a, b }
            | ConcatHelper { a, b } => {
                *a = self.make_relative(*a);
                *b = self.make_relative(*b);
                self.id_counter += 1;
            }
            PushPathConstraint { constraint: op, .. } => {
                *op = self.make_relative(*op);
            }
        }
        self.serialization_options
            .serialize_into(&mut self.writer, &message)
            .expect("unable to serialize message");
        NonZeroUsize::new(current_id).unwrap()
    }
}

impl<T: ShMem> MessageFileWriter<ShmemCursor<T>> {
    pub fn new_from_shmem(shmem: T) -> Self {
        Self::new_from_writer(ShmemCursor::from_shmem(shmem))
    }
}

impl MessageFileWriter<ShmemCursor<<StdShMemProvider as ShMemProvider>::Mem>> {
    pub fn new_from_stdshmem_env(env_name: impl AsRef<str>) -> Self {
        Self::new_from_shmem(
            StdShMemProvider::new()
                .expect("unable to initialize StdShMemProvider")
                .existing_from_env(env_name.as_ref())
                .expect("unable to get shared memory from env"),
        )
    }
}

use libafl::bolts::shmem::{ShMem, ShMemProvider, ShmemCursor, StdShMemProvider};

pub type StdShMemMessageFileWriter = MessageFileWriter<ShmemCursor<<StdShMemProvider as ShMemProvider>::Mem>>;
