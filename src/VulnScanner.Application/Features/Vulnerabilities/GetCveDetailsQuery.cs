using MediatR;
using VulnScanner.Domain.Entities;

namespace VulnScanner.Application.Features.Vulnerabilities;

public record GetCveDetailsQuery(string CveId) : IRequest<CveEntry?>;
