using VulnScanner.Domain.Enums;

namespace VulnScanner.Domain.Entities;

public class ScanResult
{
    public string ScanId { get; set; } = Guid.NewGuid().ToString();
    public DateTime ScannedAt { get; set; } = DateTime.UtcNow;
    public string FileName { get; set; } = string.Empty;
    public List<Vulnerability> Vulnerabilities { get; set; } = new();
    public int TotalFound => Vulnerabilities.Count;
    public int CriticalCount => Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Critical);
    public int HighCount => Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.High);
    public int MediumCount => Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Medium);
    public int LowCount => Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Low);
}
