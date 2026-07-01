mod javascript;
pub mod shared; 
mod typescript;
mod golang;
pub use javascript::js_scanner::JavaScriptScanner;
pub use typescript::ts_scanner::TypeScriptScanner;
pub use golang::go_scanner::GolangScanner;


pub trait Scanner{
    fn scan(&self, code:&str, file_path:&str) -> Vec<crate::server::models::findings::Findings>;
}

