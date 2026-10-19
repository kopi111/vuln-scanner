using System.Net.Http.Json;
using VulnScanner.Domain.Entities;

namespace VulnScanner.Infrastructure.ExternalApis;

public interface IOsvClient
{
    Task<List<OsvVulnerability>> QueryPackageAsync(string packageName, string version);
}

public class OsvVulnerability
{
    public string CveId { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? Severity { get; set; }
    public string? FixedVersion { get; set; }
    public List<string> References { get; set; } = new();
}

public class OsvClient : IOsvClient
{
    private readonly HttpClient _http;

    public OsvClient(HttpClient http)
    {
        _http = http;
    }

    public async Task<List<OsvVulnerability>> QueryPackageAsync(string packageName, string version)
    {
        try
        {
            var request = new
            {
                version = version,
                package = new { name = packageName, ecosystem = "NuGet" }
            };

            var response = await _http.PostAsJsonAsync("https://api.osv.dev/v1/query", request);
            if (!response.IsSuccessStatusCode) return new List<OsvVulnerability>();

            var data = await response.Content.ReadFromJsonAsync<OsvQueryResponse>();
            if (data?.Vulns == null) return new List<OsvVulnerability>();

            return data.Vulns.Select(v => new OsvVulnerability
            {
                CveId = v.Aliases?.FirstOrDefault(a => a.StartsWith("CVE-")) ?? v.Id,
                Description = v.Summary ?? v.Details ?? "No description available.",
                Severity = v.Severity?.FirstOrDefault()?.Score,
                FixedVersion = v.Affected?.SelectMany(a => a.Ranges ?? new())
                    .SelectMany(r => r.Events ?? new())
                    .FirstOrDefault(e => e.Fixed != null)?.Fixed,
                References = v.References?.Select(r => r.Url).ToList() ?? new()
            }).ToList();
        }
        catch
        {
            return new List<OsvVulnerability>();
        }
    }
}

// OSV API response models
public class OsvQueryResponse { public List<OsvEntry>? Vulns { get; set; } }
public class OsvEntry
{
    public string Id { get; set; } = string.Empty;
    public string? Summary { get; set; }
    public string? Details { get; set; }
    public List<string>? Aliases { get; set; }
    public List<OsvSeverity>? Severity { get; set; }
    public List<OsvAffected>? Affected { get; set; }
    public List<OsvReference>? References { get; set; }
}
public class OsvSeverity { public string? Score { get; set; } }
public class OsvAffected { public List<OsvRange>? Ranges { get; set; } }
public class OsvRange { public List<OsvEvent>? Events { get; set; } }
public class OsvEvent { public string? Fixed { get; set; } }
public class OsvReference { public string Url { get; set; } = string.Empty; }
