using Microsoft.Extensions.DependencyInjection;
using VulnScanner.Domain.Interfaces;
using VulnScanner.Infrastructure.CodeAnalysis;
using VulnScanner.Infrastructure.DependencyScanning;
using VulnScanner.Infrastructure.ExternalApis;

namespace VulnScanner.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services)
    {
        services.AddScoped<ICodeScanner, RoslynCodeScanner>();
        services.AddScoped<IOsvClient, OsvClient>();
        services.AddScoped<IDependencyScanner, NuGetDependencyScanner>();

        services.AddHttpClient<OsvClient>();
        services.AddHttpClient<NvdClient>();
        services.AddHttpClient<GitHubAdvisoryClient>();
        services.AddHttpClient<CisaKevClient>();
        services.AddHttpClient<MsrcClient>();

        services.AddScoped<IVulnerabilityFeedService, NvdClient>();
        services.AddScoped<IGitHubAdvisoryClient, GitHubAdvisoryClient>();
        services.AddScoped<ICisaKevClient, CisaKevClient>();
        services.AddScoped<IMsrcClient, MsrcClient>();

        return services;
    }
}
