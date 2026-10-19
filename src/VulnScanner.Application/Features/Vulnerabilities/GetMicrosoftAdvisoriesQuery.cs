using MediatR;
using VulnScanner.Domain.Entities;

namespace VulnScanner.Application.Features.Vulnerabilities;

public record GetMicrosoftAdvisoriesQuery(int? Year = null, int? Month = null) : IRequest<List<CveEntry>>;
