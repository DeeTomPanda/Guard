use crate::server::models::findings::*;
use serde_sarif::sarif::{
    ArtifactLocation, Location, Message, PhysicalLocation, Region,
    ReportingDescriptor, Result as SarifResult, Run, Sarif, Tool, ToolComponent,
};

pub fn to_sarif(all_findings: &[FinalFindings]) -> Sarif {
    let mut seen_rules = std::collections::HashSet::new();
    let mut rules = Vec::new();
    let mut results = Vec::new();

    for file_findings in all_findings {
        for finding in &file_findings.findings {
            let rule_id = finding.vuln_type.rule_id();

            if seen_rules.insert(rule_id) {
                rules.push(
                    ReportingDescriptor::builder()
                        .id(rule_id.to_string())
                        .name(finding.vuln_type.rule_name().to_string())
                        .build()
                );
            }

            let region = Region::builder()
                .start_line(finding.line_no.parse::<i64>().unwrap_or(1))
                .build();

            let location = Location::builder()
                .physical_location(
                    PhysicalLocation::builder()
                        .artifact_location(
                            ArtifactLocation::builder()
                                .uri(finding.file_path.clone())
                                .build()
                        )
                        .region(region)
                        .build()
                )
                .build();

            results.push(
                SarifResult::builder()
                    .rule_id(rule_id.to_string())
                    .message(
                        Message::builder()
                            .text(finding.snippet.clone())
                            .build()
                    )
                    .locations(vec![location])
                    .build()
            );
        }
    }

    let driver = ToolComponent::builder()
        .name("Guard".to_string())
        .rules(rules)
        .build() ;

    let tool = Tool::builder().driver(driver).build();

    let run = Run::builder().tool(tool).results(results).build();

    Sarif::builder()
        .version("2.1.0".to_string())
        .runs(vec![run])
        .build()
        
}

pub fn to_sarif_json(all_findings: &[FinalFindings]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&to_sarif(all_findings))
}
