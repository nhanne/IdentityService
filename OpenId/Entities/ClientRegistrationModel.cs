namespace OpenId.Entities;

public class ClientRegistrationModel
{
    public string ClientId { get; set; } = Guid.NewGuid().ToString();
    public string ClientSecret { get; set; } = Guid.NewGuid().ToString();
    public string DisplayName { get; set; } = string.Empty;
    public string? Grant_Type { get; set; }
    public string? Username { get; set; }
    public string? Password { get; set; }

}
