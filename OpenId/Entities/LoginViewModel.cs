using System.ComponentModel.DataAnnotations;

namespace OpenId.Entities;

public class LoginViewModel
{
    [Required]
    public string Username { get; set; } = string.Empty;
    [Required]
    public string Password { get; set; } = string.Empty;
    public string? ReturnUrl { get; set; } = string.Empty;
}
