using MediatR;
using Microsoft.AspNetCore.Mvc;
using VulnScanner.Application.Features.CodeScan;
using VulnScanner.Application.Features.DependencyScan;

namespace VulnScanner.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ScanController : ControllerBase
{
    private readonly IMediator _mediator;

    public ScanController(IMediator mediator)
    {
        _mediator = mediator;
    }

    /// <summary>Scan C# code for vulnerabilities</summary>
    [HttpPost("code")]
    public async Task<IActionResult> ScanCode([FromBody] ScanCodeRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Code))
            return BadRequest("Code content is required.");

        var result = await _mediator.Send(new ScanCodeCommand(request.Code, request.FileName ?? "code.cs"));
        return Ok(result);
    }

    /// <summary>Scan .csproj file for vulnerable NuGet dependencies</summary>
    [HttpPost("project")]
    public async Task<IActionResult> ScanProject([FromBody] ScanProjectRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.ProjectFileContent))
            return BadRequest("Project file content is required.");

        var result = await _mediator.Send(new ScanDependenciesCommand(request.ProjectFileContent, request.FileName ?? "project.csproj"));
        return Ok(result);
    }
}

public record ScanCodeRequest(string Code, string? FileName);
public record ScanProjectRequest(string ProjectFileContent, string? FileName);
