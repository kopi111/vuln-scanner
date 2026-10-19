using VulnScanner.Domain.Entities;

namespace VulnScanner.Domain.Interfaces;

public interface IMsrcClient
{
    Task<List<CveEntry>> GetLatestMicrosoftAdvisoriesAsync();
    Task<List<CveEntry>> GetAdvisoriesByMonthAsync(int year, int month);
}
