using System.Net.Http.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using AuthServiceAPI.Models;
using AuthServiceAPI.Services;

public class LoginService : ILoginService
{
    private readonly IHttpClientFactory _clientFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<LoginService> _logger;

    public LoginService(IHttpClientFactory clientFactory, IConfiguration config, ILogger<LoginService> logger)
    {
        _clientFactory = clientFactory;
        _config = config;
        _logger = logger;
    }

    public async Task<string?> AuthenticateAsync(Login login)
    {
        var client = _clientFactory.CreateClient();
        var userServiceUrl = _config["UserServiceUrl"];
        var validateUrl = $"{userServiceUrl}/users/validate";

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