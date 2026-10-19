using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class LdapInjectionAnalyzer : ISyntaxAnalyzer
{
    public IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName)
    {
        var vulnerabilities = new List<Vulnerability>();

        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var invocation in invocations)
        {
            var text = invocation.ToString();
            if ((text.Contains("DirectorySearcher") || text.Contains("DirectoryEntry") || text.Contains("Filter =")) &&
                (text.Contains("+") || text.Contains("$\"")))
            {
                var line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                vulnerabilities.Add(new Vulnerability
                {
                    Title = "LDAP Injection",
                    Description = "LDAP query built using string concatenation may allow LDAP injection attacks.",
                    Severity = VulnerabilitySeverity.High,
                    Category = "Injection",
                    CweId = "CWE-90",
                    LineNumber = line,
                    FilePath = fileName,
                    CodeSnippet = line <= lines.Length ? lines[line - 1].Trim() : string.Empty,
                    Recommendation = "Sanitize LDAP input by escaping special characters. Use parameterized LDAP queries where supported.",
                    References = new List<string>
                    {
                        "https://owasp.org/www-community/attacks/LDAP_Injection",
                        "https://cwe.mitre.org/data/definitions/90.html"
                    }
                });
            }
        }

        return vulnerabilities;
    }
}
