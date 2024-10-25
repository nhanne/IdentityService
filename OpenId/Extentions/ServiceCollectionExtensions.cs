using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;

namespace OpenId.Extentions;

internal static class ServiceCollectionExtensions
{
    private static IServiceCollection AddCustomDbContext(this IServiceCollection services, WebApplicationBuilder builder)
    {
        var connectString = builder.Configuration.GetConnectionString("AppDbConnection");
        services.AddDbContext<ApplicationDbContext>(options =>
        {
            options.UseNpgsql(connectString, opt => {
                opt.EnableRetryOnFailure();
            });
            options.UseOpenIddict();
        });

        services.Configure<IdentityOptions>(options =>
        {
            options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
            options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
            options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;
        });

        services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders(); 

        return services;
    }

    private static IServiceCollection AddCustomOpenIddict(this IServiceCollection services)
    {
        services.AddOpenIddict()
        .AddCore(options =>
        {
            options.UseEntityFrameworkCore()
                   .UseDbContext<ApplicationDbContext>();

        })
        .AddServer(options =>
        {
            options.SetTokenEndpointUris("connect/token");
            options.SetUserinfoEndpointUris("connect/userinfo");
            options.SetAuthorizationEndpointUris("connect/authorize");

            // Enable the flow.
            options.AllowClientCredentialsFlow();
            options.AllowPasswordFlow().AllowRefreshTokenFlow();
            options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
            options.AcceptAnonymousClients();

            options.SetAuthorizationEndpointUris("/connect/authorize")
                   .SetTokenEndpointUris("/connect/token")
                   .SetUserinfoEndpointUris("/connect/userinfo")
                   .SetLogoutEndpointUris("/connect/logout"); ;

            // Set the lifetime of your tokens
            options.SetAccessTokenLifetime(TimeSpan.FromMinutes(30));
            options.SetRefreshTokenLifetime(TimeSpan.FromDays(7));

            // Register the signing and encryption credentials.
            options.AddDevelopmentEncryptionCertificate()
                   .AddDevelopmentSigningCertificate()
                   .DisableAccessTokenEncryption();

            options.AddEphemeralEncryptionKey()
                   .AddEphemeralSigningKey()
                   .DisableAccessTokenEncryption();

            // Register the ASP.NET Core host and configure the ASP.NET Core options.
            options.UseAspNetCore()
                   .EnableTokenEndpointPassthrough()
                   .EnableAuthorizationEndpointPassthrough()
                   .EnableLogoutEndpointPassthrough();

        })
        .AddValidation(options =>
        {
            options.UseLocalServer();
            options.UseAspNetCore();
        }); ;

        services.AddAuthentication(options =>
        {
            options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
            options.DefaultAuthenticateScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;

        });

        services.AddHostedService<Worker>();

        return services;
    }

    private static IServiceCollection AddCustomSwaggerGen(this IServiceCollection services)
    {
        services.AddSwaggerGen(
        c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo { Title = "ApiPlayground", Version = "v1" });
            c.AddSecurityDefinition("oauth", new OpenApiSecurityScheme
                {
                    Flows = new OpenApiOAuthFlows
                    {
                        ClientCredentials = new OpenApiOAuthFlow
                        {
                            Scopes = new Dictionary<string, string>
                            {
                                ["api"] = "api scope description"
                            },
                            TokenUrl = new Uri("https://localhost:7037/connect/token"),
                        },
                    },
                    In = ParameterLocation.Header,
                    Name = HeaderNames.Authorization,
                    Type = SecuritySchemeType.OAuth2
                }
            );
            c.AddSecurityRequirement( new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "oauth" },
                        },
                        new[] { "api" }
                    }
                }
            );
        });

        return services;
    }

    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddCustomDbContext(builder);
        builder.Services.AddControllers();
        builder.Services.AddControllersWithViews();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddCustomSwaggerGen();
        builder.Services.AddCustomOpenIddict();
        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }
        app.UseHttpsRedirection();
        app.UseDeveloperExceptionPage();

        app.UseRouting();
        app.UseCors();

        app.UseAuthentication();
        app.UseAuthorization();
        app.MapControllers();

        return app;
    }
}
