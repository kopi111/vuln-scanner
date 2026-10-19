using MediatR;
using Microsoft.AspNetCore.Mvc;
using VulnScanner.Application.Features.Vulnerabilities;

namespace VulnScanner.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class VulnerabilitiesController : ControllerBase
{
    private readonly IMediator _mediator;

    public VulnerabilitiesController(IMediator mediator)
    {
        _mediator = mediator;
    }

    /// <summary>Get latest .NET vulnerabilities from NVD (last N days)</summary>
    [HttpGet("latest")]
    public async Task<IActionResult> GetLatest([FromQuery] int days = 30)
    {
        var result = await _mediator.Send(new GetLatestVulnerabilitiesQuery(days));
        return Ok(result);
    }

    /// <summary>Get details and recommendation for a specific CVE</summary>
    [HttpGet("{cveId}")]
    public async Task<IActionResult> GetCveDetails(string cveId)
    {
        var result = await _mediator.Send(new GetCveDetailsQuery(cveId));
        if (result == null) return NotFound($"CVE {cveId} not found.");
        return Ok(result);
    }

    /// <summary>Get latest NuGet advisories from GitHub Advisory Database</summary>
    [HttpGet("github")]
    public async Task<IActionResult> GetGitHubAdvisories([FromQuery] int perPage = 50)
    {
        var result = await _mediator.Send(new GetGitHubAdvisoriesQuery(perPage));
        return Ok(result);
    }

    /// <summary>Get CVEs that are actively being exploited in the wild (CISA KEV)</summary>
    [HttpGet("exploited")]
    public async Task<IActionResult> GetExploited([FromQuery] int days = 30)
    {
        var result = await _mediator.Send(new GetExploitedVulnerabilitiesQuery(days));
        return Ok(result);
    }

    /// <summary>Get latest Microsoft security advisories for .NET (MSRC)</summary>
    [HttpGet("microsoft")]
    public async Task<IActionResult> GetMicrosoft([FromQuery] int? year = null, [FromQuery] int? month = null)
    {
        var result = await _mediator.Send(new GetMicrosoftAdvisoriesQuery(year, month));
        return Ok(result);
    }
}
