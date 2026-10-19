using System.Xml.Linq;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;
using VulnScanner.Domain.Interfaces;
using VulnScanner.Infrastructure.ExternalApis;

namespace VulnScanner.Infrastructure.DependencyScanning;

public class NuGetDependencyScanner : IDependencyScanner
{
    private readonly IOsvClient _osvClient;

    public NuGetDependencyScanner(IOsvClient osvClient)
    {
        _osvClient = osvClient;
    }

    public async Task<ScanResult> ScanProjectFileAsync(string projectFileContent, string fileName)
    {
        var result = new ScanResult { FileName = fileName };
        var packages = ParsePackages(projectFileContent);

        foreach (var (packageName, version) in packages)
        {
            var vulns = await _osvClient.QueryPackageAsync(packageName, version);
            foreach (var v in vulns)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Title = $"Vulnerable Dependency: {packageName} {version}",
                    Description = v.Description,
                    Severity = MapSeverity(v.Severity),
                    Category = "Vulnerable and Outdated Component",
                    CweId = "CWE-1035",
                    CveId = v.CveId,
                    FilePath = fileName,
                    Recommendation = $"Upgrade {packageName} to version {v.FixedVersion ?? "latest"}. Review the advisory for details.",
                    References = v.References
                });
            }
        }

        return result;
    }

    private static List<(string Name, string Version)> ParsePackages(string content)
    {
        var packages = new List<(string, string)>();
        try
        {
            var doc = XDocument.Parse(content);
            // .csproj PackageReference format
            var refs = doc.Descendants("PackageReference");
            foreach (var r in refs)
            {
                var name = r.Attribute("Include")?.Value;
                var version = r.Attribute("Version")?.Value ?? r.Element("Version")?.Value;
                if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(version))
                    packages.Add((name, version));
            }
        }
        catch
        {
            // Ignore malformed XML
        }
        return packages;
    }

    private static VulnerabilitySeverity MapSeverity(string? severity) => severity?.ToUpper() switch
    {
        "CRITICAL" => VulnerabilitySeverity.Critical,
        "HIGH" => VulnerabilitySeverity.High,
        "MEDIUM" or "MODERATE" => VulnerabilitySeverity.Medium,
        "LOW" => VulnerabilitySeverity.Low,
        _ => VulnerabilitySeverity.Info
    };
}
