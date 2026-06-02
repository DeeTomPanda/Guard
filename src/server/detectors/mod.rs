mod eval;
mod hard_coded;
mod sql_injection;

pub use eval::Eval;
pub use hard_coded::HardCodedSecret;
pub use sql_injection::SQLInjection;


pub trait Detector{
    fn detect(&self, lines:&str, file_path:&str) -> Vec<crate::server::model::Findings>;
}

