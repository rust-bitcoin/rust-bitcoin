// SPDX-License-Identifier: CC0-1.0

//! Provides structured context for parsing errors.

use alloc::boxed::Box;
use core::fmt::Display;

/// Trait for providing structured context about parsing errors.
pub trait ParseErrorContext: Display {
    /// Describes the input format or value that was expected.
    fn expecting<'a>(&'a self) -> Box<dyn Display + 'a>
    {
        Box::new("valid data")
    }

    /// Provides a hint about what might have gone wrong.
    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        None
    }

    /// Suggests a potential fix or alternative input.
    fn change_suggestion(&self) -> Option<&'static str> {
        None
    }

    /// Provides additional context or points to relevant documentation.
    fn note(&self) -> Option<&'static str> {
        None
    }

    // Future methods like help(), change_suggestions(), notes() can be added here later.
} 