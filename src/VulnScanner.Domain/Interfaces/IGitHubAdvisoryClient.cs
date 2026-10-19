using VulnScanner.Domain.Entities;

namespace VulnScanner.Domain.Interfaces;

public interface IGitHubAdvisoryClient
{
    Task<List<CveEntry>> GetLatestNuGetAdvisoriesAsync(int perPage = 50);
    Task<CveEntry?> GetAdvisoryByGhsaIdAsync(string ghsaId);
}
