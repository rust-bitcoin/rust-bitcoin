//! Helper macros for implementing TryFrom<&str> for types with FromStr

/// Implement TryFrom<&str> and related traits for a type that has FromStr
#[macro_export]
macro_rules! impl_tryfrom_str {
    ($type:ty) => {
        impl TryFrom<&str> for $type {
            type Error = <$type as core::str::FromStr>::Err;
            
            fn try_from(s: &str) -> Result<Self, Self::Error> {
                s.parse()
            }
        }
        
        impl TryFrom<&mut str> for $type {
            type Error = <$type as core::str::FromStr>::Err;
            
            fn try_from(s: &mut str) -> Result<Self, Self::Error> {
                s.parse()
            }
        }
        
        impl TryFrom<String> for $type {
            type Error = <$type as core::str::FromStr>::Err;
            
            fn try_from(s: String) -> Result<Self, Self::Error> {
                s.parse()
            }
        }
        
        impl TryFrom<&String> for $type {
            type Error = <$type as core::str::FromStr>::Err;
            
            fn try_from(s: &String) -> Result<Self, Self::Error> {
                s.parse()
            }
        }
    };
}

pub use impl_tryfrom_str;
