//SSoT file for the macro _check_tts_eq

#[doc(hidden)]
macro_rules! _check_tts_eq {
    ($left:tt, $right:tt, $message:literal) => {
        macro_rules! token_eq {
            ($right) => {};
            ($any:tt) => {
                compile_error!($message)
            };
        }
        token_eq!($left);
    };
}