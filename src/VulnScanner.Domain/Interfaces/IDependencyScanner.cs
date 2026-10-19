using VulnScanner.Domain.Entities;

namespace VulnScanner.Domain.Interfaces;

public interface IDependencyScanner
{
    Task<ScanResult> ScanProjectFileAsync(string projectFileContent, string fileName);
}
