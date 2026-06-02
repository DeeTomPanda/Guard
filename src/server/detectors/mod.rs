mod javascript;

pub use javascript::eval::JavaSciptEval;
pub use javascript::hard_coded::JavaSciptHardCodedSecret;
pub use javascript::sql_injection::JavaSciptSQLInjection;


pub trait Detector{
    fn detect(&self, lines:&str, file_path:&str) -> Vec<crate::server::model::Findings>;
}

