using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class XssAnalyzer : ISyntaxAnalyzer
{
    private static readonly string[] RawOutputMethods =
    {
        "Response.Write", "Html.Raw", "HtmlHelper.Raw", "WriteLiteral", "InnerHtml"
    };

    public IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName)
    {
        var vulnerabilities = new List<Vulnerability>();

        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var invocation in invocations)
        {
            var text = invocation.ToString();
            if (RawOutputMethods.Any(m => text.Contains(m)))
            {
                var line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                vulnerabilities.Add(new Vulnerability
                {
                    Title = "Cross-Site Scripting (XSS)",
                    Description = "Raw/unencoded output to HTML response may allow XSS attacks.",
                    Severity = VulnerabilitySeverity.High,
                    Category = "XSS",
                    CweId = "CWE-79",
                    LineNumber = line,
                    FilePath = fileName,
                    CodeSnippet = line <= lines.Length ? lines[line - 1].Trim() : string.Empty,
                    Recommendation = "Use HtmlEncoder.Default.Encode() before writing user-supplied data to the response. Avoid Html.Raw() unless the content is fully trusted.",
                    References = new List<string>
                    {
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cwe.mitre.org/data/definitions/79.html"
                    }
                });
            }
        }

        return vulnerabilities;
    }
}
