using MediatR;
using VulnScanner.Domain.Entities;

namespace VulnScanner.Application.Features.Vulnerabilities;

public record GetGitHubAdvisoriesQuery(int PerPage = 50) : IRequest<List<CveEntry>>;
