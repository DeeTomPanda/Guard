mod golang;
mod javascript;
pub mod shared;
mod typescript;
pub use golang::go_scanner::GolangScanner;
pub use javascript::js_scanner::JavaScriptScanner;
pub use typescript::ts_scanner::TypeScriptScanner;

pub trait Scanner: Send + Sync {
    fn scan(&self, code: &str, file_path: &str) -> Vec<crate::server::models::findings::Findings>;
}
