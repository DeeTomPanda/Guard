use serde::Serialize;
use crate::Findings;

#[derive(Serialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<Run>,
}

#[derive(Serialize)]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<SarifResult>,
}

#[derive(Serialize)]
pub struct Tool {
    pub driver: Driver,
}

#[derive(Serialize)]
pub struct Driver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<Rule>,
}

#[derive(Serialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: Message,
    #[serde(rename = "fullDescription")]
    pub full_description: Message,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: DefaultConfiguration,
}

#[derive(Serialize)]
pub struct DefaultConfiguration {
    pub level: String,
}

#[derive(Serialize)]
pub struct Message {
    pub text: String,
}

#[derive(Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: Message,
    pub locations: Vec<Location>,
}

#[derive(Serialize)]
pub struct Location {
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
}

#[derive(Serialize)]
pub struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    pub region: Region,
}

#[derive(Serialize)]
pub struct ArtifactLocation {
    pub uri: String,
}

#[derive(Serialize)]
pub struct Region {
    #[serde(rename = "startLine")]
    pub start_line: u32,
}

