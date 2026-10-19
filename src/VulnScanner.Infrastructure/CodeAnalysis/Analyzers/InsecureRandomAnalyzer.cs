using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class InsecureRandomAnalyzer : ISyntaxAnalyzer
{
    public IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName)
    {
        var vulnerabilities = new List<Vulnerability>();

        var objectCreations = root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
        foreach (var creation in objectCreations)
        {
            if (creation.Type.ToString() == "Random")
            {
                var line = creation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                vulnerabilities.Add(new Vulnerability
                {
                    Title = "Insecure Random Number Generation",
                    Description = "System.Random is not cryptographically secure and must not be used for security-sensitive values.",
                    Severity = VulnerabilitySeverity.Medium,
                    Category = "Cryptographic Failure",
                    CweId = "CWE-338",
                    LineNumber = line,
                    FilePath = fileName,
                    CodeSnippet = line <= lines.Length ? lines[line - 1].Trim() : string.Empty,
                    Recommendation = "Use System.Security.Cryptography.RandomNumberGenerator for tokens, passwords, or session identifiers.",
                    References = new List<string>
                    {
                        "https://cwe.mitre.org/data/definitions/338.html"
                    }
                });
            }
        }

        return vulnerabilities;
    }
}
