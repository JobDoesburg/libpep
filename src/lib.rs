pub mod arithmetic;
pub mod elgamal;
pub mod zkps;
pub mod primitives;
pub mod proved;
pub mod high_level;
pub mod distributed;
pub mod utils;

#[cfg(feature = "wasm")]
mod wasm {
    mod arithmetic;
    mod elgamal;
    mod primitives;
    mod high_level;
    mod distributed;
}
