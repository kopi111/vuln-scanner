using MediatR;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Interfaces;

namespace VulnScanner.Application.Features.DependencyScan;

public class ScanDependenciesHandler : IRequestHandler<ScanDependenciesCommand, ScanResult>
{
    private readonly IDependencyScanner _scanner;

    public ScanDependenciesHandler(IDependencyScanner scanner)
    {
        _scanner = scanner;
    }

    public Task<ScanResult> Handle(ScanDependenciesCommand request, CancellationToken cancellationToken)
        => _scanner.ScanProjectFileAsync(request.ProjectFileContent, request.FileName);
}
