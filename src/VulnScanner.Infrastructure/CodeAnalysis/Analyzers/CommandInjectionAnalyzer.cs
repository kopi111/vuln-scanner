using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class CommandInjectionAnalyzer : ISyntaxAnalyzer
{
    public IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName)
    {
        var vulnerabilities = new List<Vulnerability>();

        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var invocation in invocations)
        {
            var text = invocation.ToString();
            if ((text.Contains("Process.Start") || text.Contains("ProcessStartInfo")) &&
                (text.Contains("+") || text.Contains("$\"")))
            {
                var line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                vulnerabilities.Add(new Vulnerability
                {
                    Title = "Command Injection",
                    Description = "Dynamic string passed to Process.Start may allow arbitrary command execution.",
                    Severity = VulnerabilitySeverity.Critical,
                    Category = "Injection",
                    CweId = "CWE-78",
                    LineNumber = line,
                    FilePath = fileName,
                    CodeSnippet = line <= lines.Length ? lines[line - 1].Trim() : string.Empty,
                    Recommendation = "Validate and sanitize all input before passing to Process.Start. Use whitelisting for allowed commands.",
                    References = new List<string>
                    {
                        "https://owasp.org/www-community/attacks/Command_Injection",
                        "https://cwe.mitre.org/data/definitions/78.html"
                    }
                });
            }
        }

        return vulnerabilities;
    }
}
