pub mod rc5;
pub mod cbc;
// Re-export public items for clean API
pub use rc5::RC5;
pub use rc5::Word;
pub use cbc::RC5CBC;

#[cfg(test)]
mod tests;