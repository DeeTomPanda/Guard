pub trait Detector{
    fn detect(&self,lines:&str,file_path:&str)->Vec<Findings>;
}