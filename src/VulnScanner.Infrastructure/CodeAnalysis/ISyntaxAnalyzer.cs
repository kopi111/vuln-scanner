using Microsoft.CodeAnalysis;
using VulnScanner.Domain.Entities;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public interface ISyntaxAnalyzer
{
    IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName);
}
