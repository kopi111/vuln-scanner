using MediatR;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Interfaces;

namespace VulnScanner.Application.Features.Vulnerabilities;

public class GetGitHubAdvisoriesHandler : IRequestHandler<GetGitHubAdvisoriesQuery, List<CveEntry>>
{
    private readonly IGitHubAdvisoryClient _client;

    public GetGitHubAdvisoriesHandler(IGitHubAdvisoryClient client)
    {
        _client = client;
    }

    public Task<List<CveEntry>> Handle(GetGitHubAdvisoriesQuery request, CancellationToken cancellationToken)
        => _client.GetLatestNuGetAdvisoriesAsync(request.PerPage);
}
