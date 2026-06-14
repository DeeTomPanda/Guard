mod javascript;
mod shared; 
mod typescript;
pub use javascript::js_scanner::JavaScriptScanner;
pub use typescript::ts_scanner::TypeScriptScanner;


pub trait Scanner{
    fn scan(&self, code:&str, file_path:&str) -> Vec<crate::server::model::Findings>;
}

