pub trait ConvertInput<I> {
    type Error;
    fn convert_from(i: I) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

pub trait ConvertInputLossy<I> {
    fn lossy_convert_from(i: I) -> Self;
}
