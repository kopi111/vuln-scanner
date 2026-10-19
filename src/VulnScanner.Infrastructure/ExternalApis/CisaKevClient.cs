using System.Net.Http.Json;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Interfaces;

namespace VulnScanner.Infrastructure.ExternalApis;

public class CisaKevClient : ICisaKevClient
{
    private readonly HttpClient _http;

    public CisaKevClient(HttpClient http)
    {
        _http = http;
    }

    public async Task<List<CveEntry>> GetExploitedVulnerabilitiesAsync()
    {
        try
        {
            var catalog = await _http.GetFromJsonAsync<KevCatalog>(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");

            if (catalog?.Vulnerabilities == null) return new List<CveEntry>();
            return catalog.Vulnerabilities.Select(MapToCveEntry).ToList();
        }
        catch
        {
            return new List<CveEntry>();
        }
    }

    public async Task<List<CveEntry>> GetRecentlyAddedAsync(int days = 30)
    {
        var all = await GetExploitedVulnerabilitiesAsync();
        var cutoff = DateTime.UtcNow.AddDays(-days);
        return all.Where(v => v.PublishedDate >= cutoff).ToList();
    }

    private static CveEntry MapToCveEntry(KevEntry k) => new()
    {
        CveId = k.CveId,
        Description = $"{k.VulnerabilityName}: {k.ShortDescription}",
        Severity = "HIGH",
        PublishedDate = DateTime.TryParse(k.DateAdded, out var d) ? d : DateTime.MinValue,
        LastModifiedDate = DateTime.TryParse(k.DateAdded, out var d2) ? d2 : DateTime.MinValue,
        AffectedProducts = new List<string> { $"{k.VendorProject} - {k.Product}" },
        Recommendation = $"ACTIVELY EXPLOITED. {k.RequiredAction} Deadline: {k.DueDate}.",
        References = new List<string> { $"https://nvd.nist.gov/vuln/detail/{k.CveId}" }
    };
}

// CISA KEV API models
public class KevCatalog
{
    public string? Title { get; set; }
    public string? CatalogVersion { get; set; }
    public List<KevEntry>? Vulnerabilities { get; set; }
}

public class KevEntry
{
    public string CveId { get; set; } = string.Empty;
    public string VendorProject { get; set; } = string.Empty;
    public string Product { get; set; } = string.Empty;
    public string VulnerabilityName { get; set; } = string.Empty;
    public string DateAdded { get; set; } = string.Empty;
    public string ShortDescription { get; set; } = string.Empty;
    public string RequiredAction { get; set; } = string.Empty;
    public string DueDate { get; set; } = string.Empty;
}
