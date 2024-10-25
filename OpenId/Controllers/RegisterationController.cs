using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenId.Entities;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenId.Controllers;

[Route("api/[controller]")]
[ApiController]
public class RegisterationController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ApplicationDbContext _applicationDbContext;
    private static bool _databaseChecked;

    public RegisterationController(
          UserManager<IdentityUser> userManager,
          ApplicationDbContext applicationDbContext,
          IOpenIddictApplicationManager applicationManager)
    {
        _userManager = userManager;
        _applicationDbContext = applicationDbContext;
        _applicationManager = applicationManager;
    }

    [HttpPost]
    [Route("RegisterUser")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
    {
        EnsureDatabaseCreated(_applicationDbContext);
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByNameAsync(model.Email);
            if (user != null)
            {
                return StatusCode(StatusCodes.Status409Conflict);
            }

            user = new IdentityUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                return Ok();
            }
            AddErrors(result);
        }

        return BadRequest(ModelState);
    }

    [HttpPost]
    [Route("RegisterClient")]
    [AllowAnonymous]
    public async Task<IActionResult> RegisterClient([FromBody] ClientRegistrationModel model)
    {
        try
        {
            EnsureDatabaseCreated(_applicationDbContext);

            await _applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = model.ClientId,
                ClientSecret = model.ClientSecret,
                DisplayName = model.DisplayName,
                Permissions =
                {
                   Permissions.Endpoints.Token,
                   Permissions.Endpoints.Authorization,
                   
                   Permissions.GrantTypes.ClientCredentials,
                   Permissions.GrantTypes.RefreshToken,
                   
                   Permissions.Prefixes.Scope + "Resourse",
                   Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                }
            });

            return Ok(model);
        }
        catch (Exception ex)
        {
            return BadRequest(ex.ToString());
        }
    }

    #region Helpers

    private static void EnsureDatabaseCreated(ApplicationDbContext context)
    {
        if (!_databaseChecked)
        {
            _databaseChecked = true;
            context.Database.EnsureCreated();
        }
    }

    private void AddErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }
    }

    #endregion

}
