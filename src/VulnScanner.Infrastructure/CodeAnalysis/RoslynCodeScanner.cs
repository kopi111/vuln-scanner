using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;
using VulnScanner.Domain.Interfaces;

namespace VulnScanner.Infrastructure.CodeAnalysis;

public class RoslynCodeScanner : ICodeScanner
{
    public async Task<ScanResult> ScanCodeAsync(string code, string fileName = "code.cs")
    {
        var result = new ScanResult { FileName = fileName };
        var tree = CSharpSyntaxTree.ParseText(code);
        var root = await tree.GetRootAsync();
        var lines = code.Split('\n');

        var analyzers = new List<ISyntaxAnalyzer>
        {
            new SqlInjectionAnalyzer(),
            new HardcodedCredentialsAnalyzer(),
            new WeakCryptoAnalyzer(),
            new InsecureDeserializationAnalyzer(),
            new CommandInjectionAnalyzer(),
            new PathTraversalAnalyzer(),
            new XxeAnalyzer(),
            new OpenRedirectAnalyzer(),
            new InsecureRandomAnalyzer(),
            new LdapInjectionAnalyzer(),
            new XssAnalyzer(),
            new SensitiveDataExposureAnalyzer(),
        };

        foreach (var analyzer in analyzers)
        {
            var findings = analyzer.Analyze(root, lines, fileName);
            result.Vulnerabilities.AddRange(findings);
        }

        return result;
    }
}
