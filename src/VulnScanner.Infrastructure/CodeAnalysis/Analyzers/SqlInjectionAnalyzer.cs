using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class SqlInjectionAnalyzer : ISyntaxAnalyzer
{
    private static readonly string[] SqlKeywords = { "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "EXECUTE", "UNION", "FROM", "WHERE" };

    public IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName)
    {
        var vulnerabilities = new List<Vulnerability>();

        // Detect string concatenation with SQL keywords in variable assignments and method calls
        var binaryExpressions = root.DescendantNodes().OfType<BinaryExpressionSyntax>()
            .Where(b => b.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.AddExpression));

        foreach (var expr in binaryExpressions)
        {
            var exprText = expr.ToString().ToUpper();
            if (SqlKeywords.Any(k => exprText.Contains(k)))
            {
                // Check if it contains a variable (not just string literals)
                var hasVariable = expr.DescendantNodes().OfType<IdentifierNameSyntax>().Any();
                if (hasVariable)
                {
                    var line = expr.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    var snippet = line <= lines.Length ? lines[line - 1].Trim() : string.Empty;

                    vulnerabilities.Add(new Vulnerability
                    {
                        Title = "SQL Injection",
                        Description = "String concatenation used to build SQL query. User input may be directly interpolated into SQL.",
                        Severity = VulnerabilitySeverity.Critical,
                        Category = "Injection",
                        CweId = "CWE-89",
                        LineNumber = line,
                        FilePath = fileName,
                        CodeSnippet = snippet,
                        Recommendation = "Use parameterized queries or an ORM (e.g., Entity Framework). Never concatenate user input into SQL strings.",
                        References = new List<string>
                        {
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cwe.mitre.org/data/definitions/89.html"
                        }
                    });
                }
            }
        }

        // Detect string interpolation with SQL keywords
        var interpolations = root.DescendantNodes().OfType<InterpolatedStringExpressionSyntax>();
        foreach (var interp in interpolations)
        {
            var text = interp.ToString().ToUpper();
            if (SqlKeywords.Any(k => text.Contains(k)))
            {
                var line = interp.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                var snippet = line <= lines.Length ? lines[line - 1].Trim() : string.Empty;

                vulnerabilities.Add(new Vulnerability
                {
                    Title = "SQL Injection via String Interpolation",
                    Description = "Interpolated string used to build SQL query. Variables inside may contain user-controlled data.",
                    Severity = VulnerabilitySeverity.Critical,
                    Category = "Injection",
                    CweId = "CWE-89",
                    LineNumber = line,
                    FilePath = fileName,
                    CodeSnippet = snippet,
                    Recommendation = "Replace with parameterized queries using SqlCommand.Parameters or an ORM.",
                    References = new List<string>
                    {
                        "https://owasp.org/www-community/attacks/SQL_Injection"
                    }
                });
            }
        }

        return vulnerabilities;
    }
}
