using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class SensitiveDataExposureAnalyzer : ISyntaxAnalyzer
{
    private static readonly string[] SensitivePatterns =
    {
        "console.log", "Console.Write", "Debug.Print", "Trace.Write", "logger.LogDebug"
    };

    private static readonly string[] SensitiveKeywords =
    {
        "password", "creditcard", "ssn", "token", "secret", "private"
    };

    public IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName)
    {
        var vulnerabilities = new List<Vulnerability>();

        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var invocation in invocations)
        {
            var text = invocation.ToString().ToLower();
            if (SensitivePatterns.Any(p => text.Contains(p.ToLower())) &&
                SensitiveKeywords.Any(k => text.Contains(k)))
            {
                var line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                vulnerabilities.Add(new Vulnerability
                {
                    Title = "Sensitive Data Exposure via Logging",
                    Description = "Sensitive data (password, token, etc.) may be written to logs or console output.",
                    Severity = VulnerabilitySeverity.High,
                    Category = "Sensitive Data Exposure",
                    CweId = "CWE-532",
                    LineNumber = line,
                    FilePath = fileName,
                    CodeSnippet = line <= lines.Length ? lines[line - 1].Trim() : string.Empty,
                    Recommendation = "Never log sensitive fields. Mask or redact sensitive data before logging.",
                    References = new List<string>
                    {
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                        "https://cwe.mitre.org/data/definitions/532.html"
                    }
                });
            }
        }

        return vulnerabilities;
    }
}
