using MediatR;
using VulnScanner.Domain.Entities;

namespace VulnScanner.Application.Features.CodeScan;

public record ScanCodeCommand(string Code, string FileName = "code.cs") : IRequest<ScanResult>;
