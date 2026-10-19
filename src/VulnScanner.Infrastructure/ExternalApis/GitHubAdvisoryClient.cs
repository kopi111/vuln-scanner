using System.Net.Http.Json;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Interfaces;

namespace VulnScanner.Infrastructure.ExternalApis;

public class GitHubAdvisoryClient : IGitHubAdvisoryClient
{
    private readonly HttpClient _http;

    public GitHubAdvisoryClient(HttpClient http)
    {
        _http = http;
        _http.DefaultRequestHeaders.Add("User-Agent", "VulnScanner/1.0");
    }

    public async Task<List<CveEntry>> GetLatestNuGetAdvisoriesAsync(int perPage = 50)
    {
        try
        {
            var url = $"https://api.github.com/advisories?ecosystem=nuget&per_page={perPage}&sort=published&direction=desc";
            var advisories = await _http.GetFromJsonAsync<List<GitHubAdvisory>>(url);
            if (advisories == null) return new List<CveEntry>();
            return advisories.Select(MapToCveEntry).ToList();
        }
        catch
        {
            return new List<CveEntry>();
        }
    }

    public async Task<CveEntry?> GetAdvisoryByGhsaIdAsync(string ghsaId)
    {
        try
        {
            var url = $"https://api.github.com/advisories/{ghsaId}";
            var advisory = await _http.GetFromJsonAsync<GitHubAdvisory>(url);
            return advisory != null ? MapToCveEntry(advisory) : null;
        }
        catch
        {
            return null;
        }
    }

    private static CveEntry MapToCveEntry(GitHubAdvisory a) => new()
    {
        CveId = a.CveId ?? a.GhsaId,
        Description = a.Summary ?? a.Description ?? "No description available.",
        CvssScore = a.CvssScore,
        Severity = a.Severity,
        PublishedDate = a.PublishedAt,
        LastModifiedDate = a.UpdatedAt,
        AffectedProducts = a.Vulnerabilities?.Select(v => $"{v.Package?.Name} ({v.Package?.Ecosystem})").ToList() ?? new(),
        Recommendation = BuildRecommendation(a),
        References = a.References ?? new()
    };

    private static string BuildRecommendation(GitHubAdvisory a)
    {
        var fixedVersions = a.Vulnerabilities?
            .Where(v => v.FirstPatchedVersion != null)
            .Select(v => $"{v.Package?.Name} >= {v.FirstPatchedVersion?.Identifier}")
            .ToList() ?? new();

        var fix = fixedVersions.Any()
            ? $"Upgrade to: {string.Join(", ", fixedVersions)}."
            : "No patch available yet — apply workarounds from the advisory.";

        return $"{fix} Review full advisory at https://github.com/advisories/{a.GhsaId}";
    }
}

// GitHub Advisory API models
public class GitHubAdvisory
{
    public string GhsaId { get; set; } = string.Empty;
    public string? CveId { get; set; }
    public string? Summary { get; set; }
    public string? Description { get; set; }
    public string? Severity { get; set; }
    public double? CvssScore { get; set; }
    public DateTime PublishedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public List<string>? References { get; set; }
    public List<GitHubVulnerability>? Vulnerabilities { get; set; }
}

public class GitHubVulnerability
{
    public GitHubPackage? Package { get; set; }
    public GitHubPatchedVersion? FirstPatchedVersion { get; set; }
}

public class GitHubPackage
{
    public string? Name { get; set; }
    public string? Ecosystem { get; set; }
}

public class GitHubPatchedVersion
{
    public string? Identifier { get; set; }
}
