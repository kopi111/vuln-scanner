using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class WeakCryptoAnalyzer : ISyntaxAnalyzer
{
    private static readonly string[] WeakAlgorithms = { "MD5", "SHA1", "DES", "RC2", "RC4", "TripleDES", "3DES" };

    public IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName)
    {
        var vulnerabilities = new List<Vulnerability>();

        var memberAccesses = root.DescendantNodes().OfType<MemberAccessExpressionSyntax>();
        foreach (var access in memberAccesses)
        {
            var text = access.ToString();
            foreach (var algo in WeakAlgorithms)
            {
                if (text.Contains(algo, StringComparison.OrdinalIgnoreCase))
                {
                    var line = access.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    vulnerabilities.Add(new Vulnerability
                    {
                        Title = $"Weak Cryptographic Algorithm: {algo}",
                        Description = $"Use of {algo} which is considered cryptographically weak and vulnerable to collision/brute-force attacks.",
                        Severity = VulnerabilitySeverity.High,
                        Category = "Cryptographic Failure",
                        CweId = "CWE-327",
                        LineNumber = line,
                        FilePath = fileName,
                        CodeSnippet = line <= lines.Length ? lines[line - 1].Trim() : string.Empty,
                        Recommendation = $"Replace {algo} with SHA-256 or SHA-512 for hashing. Use AES-256 for symmetric encryption.",
                        References = new List<string>
                        {
                            "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                            "https://cwe.mitre.org/data/definitions/327.html"
                        }
                    });
                    break;
                }
            }
        }

        return vulnerabilities;
    }
}
