using System.Net.Http.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using AuthServiceAPI.Models;
using AuthServiceAPI.Services;

/// <summary>
/// Service til håndtering af login og token-generering.
/// Kommunikerer med en ekstern UserService for at validere brugere.
/// </summary>
public class LoginService : ILoginService
{
    private readonly IHttpClientFactory _clientFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<LoginService> _logger;

    /// <summary>
    /// Constructor for LoginService. Injicerer HTTPClientFactory, konfiguration og logger.
    /// </summary>
    public LoginService(IHttpClientFactory clientFactory, IConfiguration config, ILogger<LoginService> logger)
    {
        _clientFactory = clientFactory;
        _config = config;
        _logger = logger;
    }

    /// <summary>
    /// Autentificerer brugeren ved at sende loginoplysninger til UserService.
    /// Returnerer et JWT-token hvis login er gyldigt.
    /// </summary>
    /// <param name="login">Login-model med brugernavn og adgangskode.</param>
    /// <returns>JWT-token som string, eller null hvis login fejler.</returns>
    public async Task<string?> AuthenticateAsync(Login login)
    {
        var client = _clientFactory.CreateClient();
        var userServiceUrl = _config["UserServiceUrl"];
        var validateUrl = $"{userServiceUrl}/api/users/validate";

        var response = await client.PostAsJsonAsync(validateUrl, login);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("Invalid credentials returned from UserService.");
            return null;
        }

        var user = await response.Content.ReadFromJsonAsync<ValidatedUserResponse>();
        if (user == null)
        {
            _logger.LogError("Deserialization failed from UserService.");
            return null;
        }

        return GenerateJwtToken(user.Username, user.Role);
    }

    /// <summary>
    /// Genererer et JWT-token baseret på brugernavn og rolle.
    /// Tokenet inkluderer claims og udløber efter 15 minutter.
    /// </summary>
    /// <param name="username">Brugerens navn.</param>
    /// <param name="role">Brugerens rolle.</param>
    /// <returns>JWT-token som string.</returns>
    private string GenerateJwtToken(string username, string role)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Secret"]));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, username),
            new Claim(ClaimTypes.Role, role)
        };

        var token = new JwtSecurityToken(
            issuer: _config["Issuer"],
            audience: _config["Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
