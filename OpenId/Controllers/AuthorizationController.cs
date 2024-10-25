using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

namespace OpenId.Controllers;

public class AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager) : ControllerBase
{
    private static ClaimsIdentity _identity = new ClaimsIdentity();
    private readonly IOpenIddictApplicationManager _applicationManager = applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager = authorizationManager;

    [HttpPost]
    [Route("connect/token")]
    [Consumes("application/x-www-form-urlencoded")]
    [Produces("application/json")]
    public async Task<IActionResult> ConnectToken()
    {
        try
        {
            var openIdConnectRequest = HttpContext.GetOpenIddictServerRequest() ??
                     throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            _identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
            IdentityUser? user = null;
            AuthenticationProperties properties = new();

            if (openIdConnectRequest.IsClientCredentialsGrantType())
            {
                _identity.SetScopes(openIdConnectRequest.GetScopes());
                _identity.SetResources(await scopeManager.ListResourcesAsync(_identity.GetScopes()).ToListAsync());

                // Add mandatory Claims
                _identity.AddClaim(new Claim(Claims.Subject, openIdConnectRequest.ClientId!));
                _identity.AddClaim(new Claim(Claims.Audience, "Resourse"));

                _identity.SetDestinations(GetDestinations);
                
            }
            else if (openIdConnectRequest.IsPasswordGrantType())
            {
                user = await userManager.FindByNameAsync(openIdConnectRequest.Username!);

                if (user == null)
                {
                    return BadRequest(new OpenIddictResponse
                    {
                        Error = Errors.InvalidGrant,
                        ErrorDescription = "User does not exist"
                    });
                }

                // Check that the user can sign in and is not locked out.
                // If two-factor authentication is supported, it would also be appropriate to check that 2FA is enabled for the user
                if (!await signInManager.CanSignInAsync(user) || 
                    (userManager.SupportsUserLockout && await userManager.IsLockedOutAsync(user)))
                {
                    // Return bad request is the user can't sign in
                    return BadRequest(new OpenIddictResponse
                    {
                        Error = Errors.InvalidGrant,
                        ErrorDescription = "The specified user cannot sign in."
                    });
                }

                // Validate the username/password parameters and ensure the account is not locked out.
                var result = await signInManager
                    .PasswordSignInAsync(user.UserName!, openIdConnectRequest.Password!, false, lockoutOnFailure: false);

                // Check bool login
                if (!result.Succeeded)
                {
                    if (result.IsNotAllowed)
                    {
                        return BadRequest(new OpenIddictResponse
                        {
                            Error = Errors.InvalidGrant,
                            ErrorDescription = "User not allowed to login. Please confirm your email"
                        });
                    }

                    if (result.RequiresTwoFactor)
                    {
                        return BadRequest(new OpenIddictResponse
                        {
                            Error = Errors.InvalidGrant,
                            ErrorDescription = "User requires 2F authentication"
                        });
                    }

                    if (result.IsLockedOut)
                    {
                        return BadRequest(new OpenIddictResponse
                        {
                            Error = Errors.InvalidGrant,
                            ErrorDescription = "User is locked out"
                        });
                    }
                    else
                    {
                        return BadRequest(new OpenIddictResponse
                        {
                            Error = Errors.InvalidGrant,
                            ErrorDescription = "Username or password is incorrect"
                        });
                    }
                }

                // The user is now validated, so reset lockout counts, if necessary
                if (userManager.SupportsUserLockout)
                {
                    await userManager.ResetAccessFailedCountAsync(user);
                }

                //// Getting scopes from user parameters (TokenViewModel) and adding in Identity 
                _identity.SetScopes(openIdConnectRequest.GetScopes());
                if (openIdConnectRequest.Scope != null && openIdConnectRequest.Scope.Split(' ').Contains(Scopes.OfflineAccess))
                {
                    _identity.SetScopes(Scopes.OfflineAccess);
                }
                _identity.SetResources(await scopeManager.ListResourcesAsync(_identity.GetScopes()).ToListAsync());

                _identity.AddClaim(new Claim(Claims.Subject, user.Id));
                _identity.AddClaim(new Claim(Claims.Audience, "Resourse"));

                // Setting destinations of claims i.e. identity token or access token
                _identity.SetDestinations(GetDestinations);

            }
            else if (openIdConnectRequest.IsRefreshTokenGrantType())
            {
                var authenticateResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                if (authenticateResult.Succeeded && authenticateResult.Principal != null)
                {
                    // Retrieve the user profile corresponding to the authorization code/refresh token.
                    user = await userManager.FindByIdAsync(authenticateResult.Principal.GetClaim(Claims.Subject));
                    if (user is null)
                    {
                        return BadRequest(new OpenIddictResponse
                        {
                            Error = Errors.InvalidGrant,
                            ErrorDescription = "The token is no longer valid."
                        });
                    }

                    // You have to grant the 'offline_access' scope to allow
                    // OpenIddict to return a refresh token to the caller.
                    _identity.SetScopes(OpenIddictConstants.Scopes.OfflineAccess);

                    _identity.AddClaim(new Claim(Claims.Subject, user.Id));
                    _identity.AddClaim(new Claim(Claims.Audience, "Resourse"));

                    // Getting scopes from user parameters (TokenViewModel)
                    // Checking in OpenIddictScopes tables for matching resources
                    // Adding in Identity
                    _identity.SetResources(await scopeManager.ListResourcesAsync(_identity.GetScopes()).ToListAsync());

                    // Setting destinations of claims i.e. identity token or access token
                    _identity.SetDestinations(GetDestinations);
                }
                else if (authenticateResult.Failure is not null)
                {
                    var failureMessage = authenticateResult.Failure.Message;
                    var failureException = authenticateResult.Failure.InnerException;
                    return BadRequest(new OpenIddictResponse
                    {
                        Error = Errors.InvalidRequest,
                        ErrorDescription = failureMessage + failureException
                    });
                }
            }
            else if (openIdConnectRequest.IsAuthorizationCodeGrantType())
            {
                // Retrieve the claims principal stored in the authorization code
                var claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
                return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
            else
            {
                return BadRequest(new
                {
                    error = Errors.UnsupportedGrantType,
                    error_description = "The specified grant type is not supported."
                });
            }

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            var signInResult = SignIn(new ClaimsPrincipal(_identity), properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            return signInResult;
        }
        catch (Exception)
        {
            return BadRequest(new OpenIddictResponse()
            {
                Error = Errors.ServerError,
                ErrorDescription = "Invalid login attempt"
            });
        }
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Retrieve the user principal stored in the authentication cookie.
        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // If the user principal can't be extracted, redirect the user to the login page.
        if (!result.Succeeded)
        {
            return Challenge(
                authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                });
        }

        // Create a new claims principal
        var claims = new List<Claim>
        {
            // 'subject' claim which is required
            new Claim(Claims.Subject, result.Principal.Identity.Name),
            new Claim("some claim", "some value").SetDestinations(Destinations.AccessToken),
            new Claim(Claims.Email, "some@email").SetDestinations(Destinations.IdentityToken)
        };

        var claimsIdentity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        // Set requested scopes (this is not done automatically)
        claimsPrincipal.SetScopes(request.GetScopes());

        // Signing in with the OpenIddict authentiction scheme trigger OpenIddict to issue a code (which can be exchanged for an access token)
        return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo")]
    public async Task<IActionResult> Userinfo()
    {
        var claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

        return Ok(new
        {
            Name = claimsPrincipal?.GetClaim(Claims.Subject),
            Occupation = "Developer",
            Age = 43
        });
    }

    #region Private Methods

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.

        return claim.Type switch
        {
            Claims.Name or
            Claims.Subject
               => new[] { Destinations.AccessToken, Destinations.IdentityToken },

            _ => new[] { Destinations.AccessToken },
        };
    }

    private void HandleIsAuthorizationCodeGrantType()
    {

    }

    #endregion
}
