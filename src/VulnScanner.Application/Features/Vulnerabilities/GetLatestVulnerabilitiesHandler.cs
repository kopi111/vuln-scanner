using MediatR;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Interfaces;

namespace VulnScanner.Application.Features.Vulnerabilities;

public class GetLatestVulnerabilitiesHandler : IRequestHandler<GetLatestVulnerabilitiesQuery, List<CveEntry>>
{
    private readonly IVulnerabilityFeedService _feedService;

    public GetLatestVulnerabilitiesHandler(IVulnerabilityFeedService feedService)
    {
        _feedService = feedService;
    }

    public Task<List<CveEntry>> Handle(GetLatestVulnerabilitiesQuery request, CancellationToken cancellationToken)
        => _feedService.GetLatestDotNetVulnerabilitiesAsync(request.Days);
}
