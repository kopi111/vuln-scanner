using System.Net.Http.Json;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Interfaces;

namespace VulnScanner.Infrastructure.ExternalApis;

public class NvdClient : IVulnerabilityFeedService
{
    private readonly HttpClient _http;

    public NvdClient(HttpClient http)
    {
        _http = http;
    }

    public async Task<List<CveEntry>> GetLatestDotNetVulnerabilitiesAsync(int days = 30)
    {
        try
        {
            var endDate = DateTime.UtcNow;
            var startDate = endDate.AddDays(-days);
            var url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=.NET&pubStartDate={startDate:yyyy-MM-dd}T00:00:00.000&pubEndDate={endDate:yyyy-MM-dd}T23:59:59.999&resultsPerPage=50";

            var response = await _http.GetFromJsonAsync<NvdResponse>(url);
            if (response?.Vulnerabilities == null) return new List<CveEntry>();

            return response.Vulnerabilities.Select(MapToCveEntry).ToList();
        }
        catch
        {
            return new List<CveEntry>();
        }
    }

    public async Task<CveEntry?> GetCveDetailsAsync(string cveId)
    {
        try
        {
            var url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cveId}";
            var response = await _http.GetFromJsonAsync<NvdResponse>(url);
            var entry = response?.Vulnerabilities?.FirstOrDefault();
            return entry != null ? MapToCveEntry(entry) : null;
        }
        catch
        {
            return null;
        }
    }

    private static CveEntry MapToCveEntry(NvdVulnerability v)
    {
        var cve = v.Cve;
        var description = cve.Descriptions?.FirstOrDefault(d => d.Lang == "en")?.Value ?? "No description.";
        var cvss = cve.Metrics?.CvssMetricV31?.FirstOrDefault()?.CvssData;
        var score = cvss?.BaseScore;
        var severity = cvss?.BaseSeverity;

        return new CveEntry
        {
            CveId = cve.Id,
            Description = description,
            CvssScore = score,
            Severity = severity,
            PublishedDate = cve.Published,
            LastModifiedDate = cve.LastModified,
            AffectedProducts = cve.Configurations?.SelectMany(c => c.Nodes ?? new())
                .SelectMany(n => n.CpeMatch ?? new())
                .Select(c => c.Criteria)
                .Take(5)
                .ToList() ?? new(),
            Recommendation = BuildRecommendation(cve.Id, severity, score),
            References = cve.References?.Select(r => r.Url).Take(5).ToList() ?? new()
        };
    }

    private static string BuildRecommendation(string cveId, string? severity, double? score) =>
        severity?.ToUpper() switch
        {
            "CRITICAL" => $"CRITICAL severity ({score}). Apply vendor patch immediately. Review affected systems and isolate if necessary.",
            "HIGH" => $"HIGH severity ({score}). Patch within 7 days. Monitor for active exploitation.",
            "MEDIUM" => $"MEDIUM severity ({score}). Patch within 30 days during next maintenance window.",
            "LOW" => $"LOW severity ({score}). Schedule patching in next release cycle.",
            _ => $"Review {cveId} and apply available patches."
        };
}

// NVD API response models
public class NvdResponse { public List<NvdVulnerability>? Vulnerabilities { get; set; } }
public class NvdVulnerability { public NvdCve Cve { get; set; } = new(); }
public class NvdCve
{
    public string Id { get; set; } = string.Empty;
    public DateTime Published { get; set; }
    public DateTime LastModified { get; set; }
    public List<NvdDescription>? Descriptions { get; set; }
    public NvdMetrics? Metrics { get; set; }
    public List<NvdReference>? References { get; set; }
    public List<NvdConfiguration>? Configurations { get; set; }
}
public class NvdDescription { public string Lang { get; set; } = string.Empty; public string Value { get; set; } = string.Empty; }
public class NvdMetrics { public List<NvdCvssV31>? CvssMetricV31 { get; set; } }
public class NvdCvssV31 { public NvdCvssData? CvssData { get; set; } }
public class NvdCvssData { public double? BaseScore { get; set; } public string? BaseSeverity { get; set; } }
public class NvdReference { public string Url { get; set; } = string.Empty; }
public class NvdConfiguration { public List<NvdNode>? Nodes { get; set; } }
public class NvdNode { public List<NvdCpeMatch>? CpeMatch { get; set; } }
public class NvdCpeMatch { public string Criteria { get; set; } = string.Empty; }
