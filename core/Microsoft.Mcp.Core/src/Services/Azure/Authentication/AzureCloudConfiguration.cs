// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Azure.Identity;
using Azure.ResourceManager;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Mcp.Core.Areas.Server;

namespace Microsoft.Mcp.Core.Services.Azure.Authentication;

/// <summary>
/// Implementation of <see cref="IAzureCloudConfiguration"/> that reads from configuration.
/// </summary>
public class AzureCloudConfiguration : IAzureCloudConfiguration
{

    public enum AzureCloud
    {
        AzurePublicCloud,
        AzureChinaCloud,
        AzureUSGovernmentCloud,
        CustomCloud,
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureCloudConfiguration"/> class.
    /// </summary>
    /// <param name="configuration">The configuration to read from.</param>
    /// <param name="runtimeConfiguration">Optional runtime configurations that can provide the cloud configuration.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    public AzureCloudConfiguration(
        IConfiguration configuration,
        IOptions<ServerRuntimeConfiguration>? runtimeConfiguration = null,
        ILogger<AzureCloudConfiguration>? logger = null)
    {
        // Try to get cloud configuration from various sources in priority order:
        // 1. ServerRuntimeConfiguration (--cloud command line argument)
        // 2. Configuration (appsettings.json or environment variables)
        var cloudValue = runtimeConfiguration?.Value?.Cloud
            ?? configuration["AZURE_CLOUD"]
            ?? configuration["azure_cloud"]
            ?? configuration["cloud"]
            ?? configuration["Cloud"]
            ?? Environment.GetEnvironmentVariable("AZURE_CLOUD");

        var customCloudConfig = runtimeConfiguration?.Value?.CustomCloudConfig
            ?? configuration["CUSTOM_CLOUD_CONFIG"]
            ?? Environment.GetEnvironmentVariable("CUSTOM_CLOUD_CONFIG");

        (AuthorityHost, ArmEnvironment, CloudType, LogAnalyticsEndpoint, LogAnalyticsScope, ApplicationInsightsEndpoint, KustoEndpointSuffix, KustoScope) =
            ParseCloudValue(cloudValue, customCloudConfig);

        logger?.LogDebug(
            "Azure cloud configuration initialized. Cloud value: '{CloudValue}', AuthorityHost: '{AuthorityHost}', ArmEnvironment: '{ArmEnvironment}'",
            cloudValue ?? "(not specified)",
            AuthorityHost,
            ArmEnvironment);
    }

    /// <inheritdoc/>
    public Uri AuthorityHost { get; }

    /// <inheritdoc/>
    public ArmEnvironment ArmEnvironment { get; }

    public AzureCloud CloudType { get; }

    public Uri LogAnalyticsEndpoint { get; }

    /// <inheritdoc/>
    public string LogAnalyticsScope { get; }

    public Uri ApplicationInsightsEndpoint { get; }

    public string? KustoEndpointSuffix { get; }

    public string? KustoScope { get; }

    private static (Uri authorityHost, ArmEnvironment armEnvironment, AzureCloud cloudType, Uri logAnalyticsEndpoint, string logAnalyticsScope, Uri applicationInsightsEndpoint, string? kustoEndpointSuffix, string? kustoScope) ParseCloudValue(
        string? cloudValue,
        string? customCloudConfig)
    {
        if (string.IsNullOrWhiteSpace(cloudValue))
        {
            return CreateBuiltIn(AzureAuthorityHosts.AzurePublicCloud, ArmEnvironment.AzurePublicCloud, AzureCloud.AzurePublicCloud, "https://api.loganalytics.io", "https://api.applicationinsights.io");
        }

        // Map common sovereign cloud names to authority hosts and ARM environments
        return cloudValue.ToLowerInvariant() switch
        {
            "azurecloud" or "azurepubliccloud" or "public" or "azurepublic" =>
                CreateBuiltIn(AzureAuthorityHosts.AzurePublicCloud, ArmEnvironment.AzurePublicCloud, AzureCloud.AzurePublicCloud, "https://api.loganalytics.io", "https://api.applicationinsights.io"),
            "azurechinacloud" or "china" or "azurechina" =>
                CreateBuiltIn(AzureAuthorityHosts.AzureChina, ArmEnvironment.AzureChina, AzureCloud.AzureChinaCloud, "https://api.loganalytics.azure.cn", "https://api.applicationinsights.azure.cn"),
            "azureusgovernment" or "azureusgovernmentcloud" or "usgov" or "usgovernment" =>
                CreateBuiltIn(AzureAuthorityHosts.AzureGovernment, ArmEnvironment.AzureGovernment, AzureCloud.AzureUSGovernmentCloud, "https://api.loganalytics.us", "https://api.applicationinsights.us"),
            "custom" => LoadCustomCloud(customCloudConfig),
            _ => throw new ArgumentException(
                $"Unrecognized cloud value '{cloudValue}'. Supported values are: AzureCloud, AzurePublicCloud, Public, AzurePublic, AzureChinaCloud, China, AzureChina, AzureUSGovernment, AzureUSGovernmentCloud, USGov, USGovernment, custom.",
                nameof(cloudValue))
        };
    }

    private static (Uri, ArmEnvironment, AzureCloud, Uri, string, Uri, string?, string?) CreateBuiltIn(
        Uri authorityHost,
        ArmEnvironment armEnvironment,
        AzureCloud cloudType,
        string logAnalyticsEndpoint,
        string applicationInsightsEndpoint) =>
        (authorityHost, armEnvironment, cloudType, new Uri(logAnalyticsEndpoint), $"{new Uri(logAnalyticsEndpoint).AbsoluteUri.TrimEnd('/')}/.default", new Uri(applicationInsightsEndpoint), null, null);

    private static (Uri, ArmEnvironment, AzureCloud, Uri, string, Uri, string?, string?) LoadCustomCloud(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A custom cloud configuration file is required when cloud is 'custom'.", nameof(path));
        }

        var metadata = JsonSerializer.Deserialize(
            File.ReadAllText(path),
            CustomCloudMetadataJsonContext.Default.CustomCloudMetadata)
            ?? throw new ArgumentException("The custom cloud configuration file is empty.", nameof(path));

        var authorityHost = ParseHttpsUri(metadata.AuthorityHost, nameof(metadata.AuthorityHost));
        var armEndpoint = ParseHttpsUri(metadata.ArmEndpoint, nameof(metadata.ArmEndpoint));
        var logAnalyticsEndpoint = ParseHttpsUri(metadata.LogAnalyticsEndpoint, nameof(metadata.LogAnalyticsEndpoint));
        var applicationInsightsEndpoint = ParseHttpsUri(metadata.ApplicationInsightsEndpoint, nameof(metadata.ApplicationInsightsEndpoint));
        if (string.IsNullOrWhiteSpace(metadata.ResourceManagerAudience))
        {
            throw new ArgumentException("Custom cloud metadata must specify resourceManagerAudience.", nameof(path));
        }

        if (string.IsNullOrWhiteSpace(metadata.LogAnalyticsScope))
        {
            throw new ArgumentException("Custom cloud metadata must specify logAnalyticsScope.", nameof(path));
        }

        var (kustoEndpointSuffix, kustoScope) = ParseKustoMetadata(metadata);

        return (authorityHost, new ArmEnvironment(armEndpoint, metadata.ResourceManagerAudience), AzureCloud.CustomCloud, logAnalyticsEndpoint, metadata.LogAnalyticsScope, applicationInsightsEndpoint, kustoEndpointSuffix, kustoScope);
    }

    private static (string? endpointSuffix, string? scope) ParseKustoMetadata(CustomCloudMetadata metadata)
    {
        if (metadata.KustoEndpointSuffix == null && metadata.KustoScope == null)
        {
            return (null, null);
        }

        if (string.IsNullOrWhiteSpace(metadata.KustoEndpointSuffix))
        {
            throw new ArgumentException("Custom cloud metadata must specify kustoEndpointSuffix when kustoScope is configured.", nameof(metadata.KustoEndpointSuffix));
        }

        if (string.IsNullOrWhiteSpace(metadata.KustoScope))
        {
            throw new ArgumentException("Custom cloud metadata must specify kustoScope when kustoEndpointSuffix is configured.", nameof(metadata.KustoScope));
        }

        return (NormalizeKustoEndpointSuffix(metadata.KustoEndpointSuffix), ValidateKustoScope(metadata.KustoScope));
    }

    private static string NormalizeKustoEndpointSuffix(string value)
    {
        if (!value.Equals(value.Trim(), StringComparison.Ordinal) ||
            value.Any(c => c > 127) ||
            value.Contains("*", StringComparison.Ordinal) ||
            value.Contains("%", StringComparison.Ordinal) ||
            value.Contains("/", StringComparison.Ordinal) ||
            value.Contains("\\", StringComparison.Ordinal) ||
            value.Contains(":", StringComparison.Ordinal) ||
            value.Contains("@", StringComparison.Ordinal) ||
            value.Contains("?", StringComparison.Ordinal) ||
            value.Contains("#", StringComparison.Ordinal) ||
            value.EndsWith(".", StringComparison.Ordinal))
        {
            throw new ArgumentException("Custom cloud metadata property 'kustoEndpointSuffix' must be a DNS suffix.", nameof(value));
        }

        var host = value.TrimStart('.');
        if (Uri.CheckHostName(host) != UriHostNameType.Dns || host.Split('.').Length < 2)
        {
            throw new ArgumentException("Custom cloud metadata property 'kustoEndpointSuffix' must be a multi-label DNS suffix.", nameof(value));
        }

        foreach (var label in host.Split('.'))
        {
            if (label.Length is 0 or > 63 ||
                !char.IsLetterOrDigit(label[0]) ||
                !char.IsLetterOrDigit(label[^1]) ||
                label.Any(c => !char.IsLetterOrDigit(c) && c != '-'))
            {
                throw new ArgumentException("Custom cloud metadata property 'kustoEndpointSuffix' contains an invalid DNS label.", nameof(value));
            }
        }

        return $".{host.ToLowerInvariant()}";
    }

    private static string ValidateKustoScope(string value)
    {
        if (!value.Equals(value.Trim(), StringComparison.Ordinal) ||
            value.Any(c => c > 127) ||
            value.Contains("%", StringComparison.Ordinal) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            Uri.CheckHostName(uri.Host) != UriHostNameType.Dns ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            HasExplicitPort(value) ||
            !uri.AbsolutePath.EndsWith("/.default", StringComparison.Ordinal) ||
            uri.AbsolutePath.Contains("/../", StringComparison.Ordinal) ||
            uri.AbsolutePath.Contains("/./", StringComparison.Ordinal))
        {
            throw new ArgumentException("Custom cloud metadata property 'kustoScope' must be a canonical absolute HTTPS scope ending in '/.default'.", nameof(value));
        }

        return value;
    }

    private static bool HasExplicitPort(string value)
    {
        var authorityStart = Uri.UriSchemeHttps.Length + Uri.SchemeDelimiter.Length;
        var authorityEnd = value.IndexOf('/', authorityStart);
        var authority = authorityEnd < 0 ? value[authorityStart..] : value[authorityStart..authorityEnd];
        return authority.Contains(":", StringComparison.Ordinal);
    }

    private static Uri ParseHttpsUri(string? value, string propertyName)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException($"Custom cloud metadata property '{propertyName}' must be an absolute HTTPS URI.", propertyName);
        }

        return uri;
    }
}
