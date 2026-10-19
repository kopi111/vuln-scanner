using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class HardcodedCredentialsAnalyzer : ISyntaxAnalyzer
{
    private static readonly string[] CredentialKeywords =
    {
        "password", "passwd", "pwd", "secret", "apikey", "api_key", "token",
        "connectionstring", "privatekey", "accesskey", "authtoken", "clientsecret"
    };

    public IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName)
    {
        var vulnerabilities = new List<Vulnerability>();

        var assignments = root.DescendantNodes().OfType<AssignmentExpressionSyntax>();
        foreach (var assign in assignments)
        {
            var leftText = assign.Left.ToString().ToLower();
            if (CredentialKeywords.Any(k => leftText.Contains(k)))
            {
                if (assign.Right is LiteralExpressionSyntax literal &&
                    literal.Token.ValueText.Length > 3)
                {
                    var line = assign.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    vulnerabilities.Add(CreateVuln(line, lines, fileName, assign.ToString()));
                }
            }
        }

        var varDeclarators = root.DescendantNodes().OfType<VariableDeclaratorSyntax>();
        foreach (var decl in varDeclarators)
        {
            var name = decl.Identifier.Text.ToLower();
            if (CredentialKeywords.Any(k => name.Contains(k)))
            {
                if (decl.Initializer?.Value is LiteralExpressionSyntax literal &&
                    literal.Token.ValueText.Length > 3)
                {
                    var line = decl.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    vulnerabilities.Add(CreateVuln(line, lines, fileName, decl.ToString()));
                }
            }
        }

        return vulnerabilities;
    }

    private static Vulnerability CreateVuln(int line, string[] lines, string fileName, string snippet) => new()
    {
        Title = "Hardcoded Credential",
        Description = "A credential, secret, or API key appears to be hardcoded in source code.",
        Severity = VulnerabilitySeverity.Critical,
        Category = "Sensitive Data Exposure",
        CweId = "CWE-798",
        LineNumber = line,
        FilePath = fileName,
        CodeSnippet = line <= lines.Length ? lines[line - 1].Trim() : snippet,
        Recommendation = "Store secrets in environment variables, a secrets manager (Azure Key Vault, AWS Secrets Manager), or a .env file excluded from source control.",
        References = new List<string>
        {
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "https://cwe.mitre.org/data/definitions/798.html"
        }
    };
}
