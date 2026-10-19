using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class OpenRedirectAnalyzer : ISyntaxAnalyzer
{
    public IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName)
    {
        var vulnerabilities = new List<Vulnerability>();

        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var invocation in invocations)
        {
            var text = invocation.ToString();
            if ((text.Contains("Redirect(") || text.Contains("RedirectToAction(") || text.Contains("Response.Redirect(")) &&
                !text.Contains("Url.IsLocalUrl"))
            {
                var args = invocation.ArgumentList.Arguments;
                foreach (var arg in args)
                {
                    if (arg.Expression is IdentifierNameSyntax ||
                        arg.Expression is MemberAccessExpressionSyntax)
                    {
                        var line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                        vulnerabilities.Add(new Vulnerability
                        {
                            Title = "Open Redirect",
                            Description = "Redirect target may be user-controlled, enabling phishing attacks.",
                            Severity = VulnerabilitySeverity.Medium,
                            Category = "Open Redirect",
                            CweId = "CWE-601",
                            LineNumber = line,
                            FilePath = fileName,
                            CodeSnippet = line <= lines.Length ? lines[line - 1].Trim() : string.Empty,
                            Recommendation = "Validate redirect URLs using Url.IsLocalUrl() before redirecting, or use a whitelist of allowed redirect targets.",
                            References = new List<string>
                            {
                                "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
                                "https://cwe.mitre.org/data/definitions/601.html"
                            }
                        });
                        break;
                    }
                }
            }
        }

        return vulnerabilities;
    }
}
