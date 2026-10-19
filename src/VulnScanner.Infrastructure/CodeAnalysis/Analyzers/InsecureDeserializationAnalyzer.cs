using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class InsecureDeserializationAnalyzer : ISyntaxAnalyzer
{
    private static readonly string[] DangerousTypes =
    {
        "BinaryFormatter", "SoapFormatter", "NetDataContractSerializer",
        "ObjectStateFormatter", "LosFormatter", "JavaScriptSerializer"
    };

    public IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName)
    {
        var vulnerabilities = new List<Vulnerability>();

        var identifiers = root.DescendantNodes().OfType<IdentifierNameSyntax>();
        foreach (var id in identifiers)
        {
            if (DangerousTypes.Contains(id.Identifier.Text))
            {
                var line = id.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                vulnerabilities.Add(new Vulnerability
                {
                    Title = $"Insecure Deserialization: {id.Identifier.Text}",
                    Description = $"{id.Identifier.Text} is known to be vulnerable to deserialization attacks and remote code execution.",
                    Severity = VulnerabilitySeverity.Critical,
                    Category = "Insecure Deserialization",
                    CweId = "CWE-502",
                    LineNumber = line,
                    FilePath = fileName,
                    CodeSnippet = line <= lines.Length ? lines[line - 1].Trim() : string.Empty,
                    Recommendation = "Use System.Text.Json or Newtonsoft.Json with TypeNameHandling.None. Avoid BinaryFormatter entirely — it is disabled by default in .NET 5+.",
                    References = new List<string>
                    {
                        "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                        "https://cwe.mitre.org/data/definitions/502.html"
                    }
                });
            }
        }

        return vulnerabilities;
    }
}
