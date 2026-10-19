using MediatR;
using VulnScanner.Domain.Entities;

namespace VulnScanner.Application.Features.DependencyScan;

public record ScanDependenciesCommand(string ProjectFileContent, string FileName) : IRequest<ScanResult>;
