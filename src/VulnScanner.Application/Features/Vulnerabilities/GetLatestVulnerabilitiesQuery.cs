using MediatR;
using VulnScanner.Domain.Entities;

namespace VulnScanner.Application.Features.Vulnerabilities;

public record GetLatestVulnerabilitiesQuery(int Days = 30) : IRequest<List<CveEntry>>;
