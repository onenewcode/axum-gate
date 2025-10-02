/// Conversion between a model and its CSV representation.
pub trait CommaSeparatedValue
where
    Self: Sized,
{
    /// Converts `self` into a comma separated value.
    fn into_csv(self) -> String;
    /// Converts the given slice into the model.
    fn from_csv(value: &str) -> Result<Self, String>;
}
