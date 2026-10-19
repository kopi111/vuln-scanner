using MediatR;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Interfaces;

namespace VulnScanner.Application.Features.Vulnerabilities;

public class GetCveDetailsHandler : IRequestHandler<GetCveDetailsQuery, CveEntry?>
{
    private readonly IVulnerabilityFeedService _feedService;

    public GetCveDetailsHandler(IVulnerabilityFeedService feedService)
    {
        _feedService = feedService;
    }

    public Task<CveEntry?> Handle(GetCveDetailsQuery request, CancellationToken cancellationToken)
        => _feedService.GetCveDetailsAsync(request.CveId);
}
