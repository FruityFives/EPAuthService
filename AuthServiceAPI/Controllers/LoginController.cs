using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using AuthServiceAPI.Models;
using AuthServiceAPI.Services;

namespace AuthServiceAPI.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class LoginController : ControllerBase
    {
        private readonly ILoginService _loginService;
        private readonly ILogger<LoginController> _logger;

        /// <summary>
        /// Constructor for LoginController. Injicerer login service og logger.
        /// </summary>
        public LoginController(ILoginService loginService, ILogger<LoginController> logger)
        {
            _loginService = loginService;
            _logger = logger;
        }

        /// <summary>
        /// Autentificerer en bruger og returnerer et JWT-token ved gyldige loginoplysninger.
        /// </summary>
        /// <param name="login">Login-model med brugernavn og adgangskode.</param>
        /// <returns>
        /// 200 OK med token hvis login er gyldigt.  
        /// 400 Bad Request hvis input er ugyldigt.  
        /// 401 Unauthorized hvis login fejler.
        /// </returns>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            if (login == null || string.IsNullOrWhiteSpace(login.Username) || string.IsNullOrWhiteSpace(login.Password))
            {
                _logger.LogWarning("Login attempt with invalid payload.");
                return BadRequest("Invalid login request.");
            }

            _logger.LogInformation("Login attempt for user: {Username}", login.Username);
            var token = await _loginService.AuthenticateAsync(login);

            if (token == null)
            {
                _logger.LogWarning("Authentication failed for user: {Username}", login.Username);
                return Unauthorized("Invalid credentials.");
            }

            _logger.LogInformation("Token generated successfully for user: {Username}", login.Username);
            return Ok(new { token });
        }

        /// <summary>
        /// Validerer det udstedte JWT-token og returnerer brugernavn og rolle, hvis det er gyldigt.
        /// Kun tilgængelig for brugere med rollen 'Admin'.
        /// </summary>
        /// <returns>
        /// 200 OK med brugeroplysninger hvis token er gyldigt.  
        /// 401 Unauthorized hvis token er ugyldigt eller mangler påkrævede claims.
        /// </returns>
        [Authorize(Roles = "Admin")]
        [HttpGet("validate-token")]
        public IActionResult ValidateToken()
        {
            var username = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var role = User.FindFirst(ClaimTypes.Role)?.Value;

            _logger.LogInformation("ValidateToken hit. Username: {Username}, Role: {Role}", username, role);
            _logger.LogDebug("Claims: {@Claims}", User.Claims.Select(c => new { c.Type, c.Value }));
            _logger.LogDebug("User claims count: {Count}", User.Claims.Count());
            _logger.LogDebug("User identity is authenticated: {IsAuthenticated}", User.Identity?.IsAuthenticated);

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(role))
            {
                _logger.LogWarning("Token validation failed. Missing claims.");
                return Unauthorized("Invalid token.");
            }

            return Ok(new { message = "Token is valid", username, role });
        }
    }
}
