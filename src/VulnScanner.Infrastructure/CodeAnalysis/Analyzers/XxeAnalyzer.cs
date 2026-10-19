using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class XxeAnalyzer : ISyntaxAnalyzer
{
    public IEnumerable<Vulnerability> Analyze(SyntaxNode root, string[] lines, string fileName)
    {
        var vulnerabilities = new List<Vulnerability>();

        var objectCreations = root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
        foreach (var creation in objectCreations)
        {
            var typeName = creation.Type.ToString();
            if (typeName.Contains("XmlDocument") || typeName.Contains("XmlTextReader") ||
                typeName.Contains("XPathDocument") || typeName.Contains("XmlReader"))
            {
                // Check if DtdProcessing is not explicitly set to Prohibit
                var surroundingCode = creation.Parent?.ToString() ?? string.Empty;
                if (!surroundingCode.Contains("DtdProcessing.Prohibit") &&
                    !surroundingCode.Contains("ProhibitDtd"))
                {
                    var line = creation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    vulnerabilities.Add(new Vulnerability
                    {
                        Title = "XML External Entity (XXE) Injection",
                        Description = $"{typeName} may process external XML entities if DTD processing is not disabled.",
                        Severity = VulnerabilitySeverity.High,
                        Category = "XXE",
                        CweId = "CWE-611",
                        LineNumber = line,
                        FilePath = fileName,
                        CodeSnippet = line <= lines.Length ? lines[line - 1].Trim() : string.Empty,
                        Recommendation = "Set XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit and XmlReaderSettings.XmlResolver = null.",
                        References = new List<string>
                        {
                            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                            "https://cwe.mitre.org/data/definitions/611.html"
                        }
                    });
                }
            }
        }

        return vulnerabilities;
    }
}
