using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class PathTraversalAnalyzer : ISyntaxAnalyzer
{
    private static readonly string[] FileApiMethods =
    {
        "File.ReadAllText", "File.WriteAllText", "File.ReadAllBytes", "File.WriteAllBytes",
        "File.Open", "File.Create", "File.Delete", "Directory.GetFiles",
        "Path.Combine", "FileStream", "StreamReader", "StreamWriter"
    };

    public IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName)
    {
        var vulnerabilities = new List<Vulnerability>();

        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var invocation in invocations)
        {
            var text = invocation.ToString();
            if (FileApiMethods.Any(m => text.Contains(m)) &&
                (text.Contains("+") || text.Contains("$\"")))
            {
                var line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                vulnerabilities.Add(new Vulnerability
                {
                    Title = "Path Traversal",
                    Description = "File path built from dynamic/user-controlled input may allow directory traversal attacks.",
                    Severity = VulnerabilitySeverity.High,
                    Category = "Path Traversal",
                    CweId = "CWE-22",
                    LineNumber = line,
                    FilePath = fileName,
                    CodeSnippet = line <= lines.Length ? lines[line - 1].Trim() : string.Empty,
                    Recommendation = "Validate file paths against a whitelist. Use Path.GetFullPath() and verify the result starts with the expected base directory.",
                    References = new List<string>
                    {
                        "https://owasp.org/www-community/attacks/Path_Traversal",
                        "https://cwe.mitre.org/data/definitions/22.html"
                    }
                });
            }
        }

        return vulnerabilities;
    }
}
