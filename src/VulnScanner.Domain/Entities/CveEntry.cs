namespace VulnScanner.Domain.Entities;

public class CveEntry
{
    public string CveId { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public double? CvssScore { get; set; }
    public string? Severity { get; set; }
    public DateTime PublishedDate { get; set; }
    public DateTime LastModifiedDate { get; set; }
    public List<string> AffectedProducts { get; set; } = new();
    public string Recommendation { get; set; } = string.Empty;
    public List<string> References { get; set; } = new();
}
