using VulnScanner.Domain.Entities;

namespace VulnScanner.Domain.Interfaces;

public interface ICodeScanner
{
    Task<ScanResult> ScanCodeAsync(string code, string fileName = "code.cs");
}
