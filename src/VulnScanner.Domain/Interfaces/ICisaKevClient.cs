using VulnScanner.Domain.Entities;

namespace VulnScanner.Domain.Interfaces;

public interface ICisaKevClient
{
    Task<List<CveEntry>> GetExploitedVulnerabilitiesAsync();
    Task<List<CveEntry>> GetRecentlyAddedAsync(int days = 30);
}
