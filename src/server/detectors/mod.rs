mod golang;
mod javascript;
pub mod shared;
mod typescript;
pub use golang::go_scanner::GolangScanner;
pub use javascript::js_scanner::JavaScriptScanner;
pub use typescript::ts_scanner::TypeScriptScanner;
use crate::server::models::results::ScanResult;

pub trait Scanner: Send + Sync {
    fn scan(&self, code: &str, file_path: &str) -> ScanResult;
}
