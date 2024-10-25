namespace WeatherForecast;

public class UnauthorizedRedirectMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _identityServerLoginUrl;

    public UnauthorizedRedirectMiddleware(RequestDelegate next, string identityServerLoginUrl)
    {
        _next = next;
        _identityServerLoginUrl = identityServerLoginUrl;
    }
    
    public async Task Invoke(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            if (ex.GetType() == typeof(HttpRequestException) &&
                ((HttpRequestException)ex).StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                // Redirect to Identity Server login page
                context.Response.Redirect($"{_identityServerLoginUrl}?redirect_uri={Uri.EscapeDataString(context.Request.Path)}");
                return;
            }

            throw; // Re-throw other exceptions
        }

        if (context.Response.StatusCode == (int)System.Net.HttpStatusCode.Unauthorized)
        {

            string redirectUri = context.Request.Scheme + "://" + context.Request.Host + context.Request.Path;
            context.Response.Redirect($"{_identityServerLoginUrl}?redirect_uri={Uri.EscapeDataString(redirectUri)}");


            return;
        }


    }
}
