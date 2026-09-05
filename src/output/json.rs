use crate::domain::UsageReport;
pub fn render(report: &UsageReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}
