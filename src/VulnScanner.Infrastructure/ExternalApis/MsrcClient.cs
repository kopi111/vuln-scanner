using System.Net.Http.Json;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Interfaces;

namespace VulnScanner.Infrastructure.ExternalApis;

public class MsrcClient : IMsrcClient
{
    private readonly HttpClient _http;

    public MsrcClient(HttpClient http)
    {
        _http = http;
        _http.DefaultRequestHeaders.Add("Accept", "application/json");
    }

    public async Task<List<CveEntry>> GetLatestMicrosoftAdvisoriesAsync()
    {
        var now = DateTime.UtcNow;
        return await GetAdvisoriesByMonthAsync(now.Year, now.Month);
    }

    public async Task<List<CveEntry>> GetAdvisoriesByMonthAsync(int year, int month)
    {
        try
        {
            var monthName = new DateTime(year, month, 1).ToString("MMM");
            var id = $"{year}-{monthName}";
            var url = $"https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{id}";

            var doc = await _http.GetFromJsonAsync<MsrcDocument>(url);
            if (doc?.Vulnerability == null) return new List<CveEntry>();

            return doc.Vulnerability
                .Where(v => IsDotNetRelated(v))
                .Select(MapToCveEntry)
                .ToList();
        }
        catch
        {
            return new List<CveEntry>();
        }
    }

    private static bool IsDotNetRelated(MsrcVulnerability v)
    {
        var title = v.Title?.Value?.ToLower() ?? string.Empty;
        return title.Contains(".net") || title.Contains("asp.net") ||
               title.Contains("visual studio") || title.Contains("nuget");
    }

    private static CveEntry MapToCveEntry(MsrcVulnerability v)
    {
        var cvss = v.CVSSScoreSets?.FirstOrDefault();
        var score = cvss?.BaseScore;
        var severity = score switch { >= 9.0 => "CRITICAL", >= 7.0 => "HIGH", >= 4.0 => "MEDIUM", _ => "LOW" };

        return new CveEntry
        {
            CveId = v.CVE ?? "Unknown",
            Description = v.Notes?.FirstOrDefault(n => n.Type == 1)?.Value ?? v.Title?.Value ?? "No description.",
            CvssScore = score,
            Severity = severity,
            PublishedDate = DateTime.UtcNow,
            LastModifiedDate = DateTime.UtcNow,
            AffectedProducts = new List<string> { v.Title?.Value ?? string.Empty },
            Recommendation = BuildRecommendation(v),
            References = v.Remediations?.Select(r => r.URL ?? string.Empty).Where(u => !string.IsNullOrEmpty(u)).Take(5).ToList() ?? new()
        };
    }

    private static string BuildRecommendation(MsrcVulnerability v)
    {
        var kbs = v.Remediations?
            .Where(r => r.Type == 2)
            .Select(r => r.Description?.Value)
            .Where(d => d != null)
            .Take(3)
            .ToList() ?? new();

        return kbs.Any()
            ? $"Apply Microsoft security update(s): {string.Join(", ", kbs)}. Run Windows Update or download from Microsoft Update Catalog."
            : "Apply the latest Microsoft security updates via Windows Update.";
    }
}

// MSRC API models
public class MsrcDocument { public List<MsrcVulnerability>? Vulnerability { get; set; } }
public class MsrcVulnerability
{
    public string? CVE { get; set; }
    public MsrcTitle? Title { get; set; }
    public List<MsrcNote>? Notes { get; set; }
    public List<MsrcCvssScoreSet>? CVSSScoreSets { get; set; }
    public List<MsrcRemediation>? Remediations { get; set; }
}
public class MsrcTitle { public string? Value { get; set; } }
public class MsrcNote { public int Type { get; set; } public string? Value { get; set; } }
public class MsrcCvssScoreSet { public double? BaseScore { get; set; } }
public class MsrcRemediation { public int Type { get; set; } public MsrcDescription? Description { get; set; } public string? URL { get; set; } }
public class MsrcDescription { public string? Value { get; set; } }
