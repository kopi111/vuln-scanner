using MediatR;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Interfaces;

namespace VulnScanner.Application.Features.CodeScan;

public class ScanCodeHandler : IRequestHandler<ScanCodeCommand, ScanResult>
{
    private readonly ICodeScanner _scanner;

    public ScanCodeHandler(ICodeScanner scanner)
    {
        _scanner = scanner;
    }

    public Task<ScanResult> Handle(ScanCodeCommand request, CancellationToken cancellationToken)
        => _scanner.ScanCodeAsync(request.Code, request.FileName);
}
