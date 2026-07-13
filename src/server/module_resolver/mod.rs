use crate::server::{
    guard::{Language,Guard},
    module_resolver::{go_resolver::GolangResolver, js_and_ts_resolver::JSTSResolver},
};
use std::collections::HashMap;

pub mod go_resolver;
pub mod js_and_ts_resolver;

// use these to ensure
// ease of imports resolution
pub trait LanguageResolver: Send + Sync {
    fn accepts(&self, file_path: &str) -> bool;
    fn resolve(&self, import_path: &str) -> Vec<String>;
}

pub struct ImportResolver {
    import_resolvers: HashMap<Language, Box<dyn LanguageResolver>>,
}

impl ImportResolver {
    // TODO: all get a copy of files, make it dynamic..
    pub fn new(scan_path: &str, all_files: &[String]) -> Self {
        let mut import_resolvers: HashMap<Language, Box<dyn LanguageResolver>> = HashMap::new();

        import_resolvers.insert(
            Language::JavaScript,
            Box::new(JSTSResolver::new(scan_path, all_files)),
        );
        import_resolvers.insert(
            Language::TypeScript,
            Box::new(JSTSResolver::new(scan_path, all_files)),
        );
        import_resolvers.insert(
            Language::Golang,
            Box::new(GolangResolver::new(scan_path, all_files)),
        );

        Self { import_resolvers }
    }

    pub fn resolve(&self, stem: &str, file: &str) -> Vec<String> {
        Guard::determine_language(file)
            .and_then(|lang| self.import_resolvers.get(&lang))
            .map(|r| r.resolve(stem))
            .unwrap_or_default()
    }
}
