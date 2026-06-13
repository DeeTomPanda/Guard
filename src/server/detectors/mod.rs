mod javascript;

pub use javascript::js_scanner::JavaScriptScanner;

pub trait Scanner{
    fn scan(&self, code:&str, file_path:&str) -> Vec<crate::server::model::Findings>;
}

