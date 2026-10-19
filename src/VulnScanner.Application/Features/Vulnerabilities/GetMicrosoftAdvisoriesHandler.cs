using MediatR;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Interfaces;

namespace VulnScanner.Application.Features.Vulnerabilities;

public class GetMicrosoftAdvisoriesHandler : IRequestHandler<GetMicrosoftAdvisoriesQuery, List<CveEntry>>
{
    private readonly IMsrcClient _client;

    public GetMicrosoftAdvisoriesHandler(IMsrcClient client)
    {
        _client = client;
    }

    public async Task<List<CveEntry>> Handle(GetMicrosoftAdvisoriesQuery request, CancellationToken cancellationToken)
    {
        if (request.Year.HasValue && request.Month.HasValue)
            return await _client.GetAdvisoriesByMonthAsync(request.Year.Value, request.Month.Value);
        return await _client.GetLatestMicrosoftAdvisoriesAsync();
    }
}
