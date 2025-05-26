using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using AuthServiceAPI.Models;
using AuthServiceAPI.Services; // Husk at pege korrekt til din service

namespace AuthServiceAPI.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class LoginController : ControllerBase
    {
        private readonly ILoginService _loginService;
        private readonly ILogger<LoginController> _logger;

        public LoginController(ILoginService loginService, ILogger<LoginController> logger)
        {
            _loginService = loginService;
            _logger = logger;
        }

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

        [Authorize]
        [HttpGet("validate")]
        public IActionResult ValidateToken()
        {
            var username = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var role = User.FindFirst(ClaimTypes.Role)?.Value;

            _logger.LogInformation("ValidateToken hit. Username: {Username}, Role: {Role}", username, role);

            if (string.IsNullOrEmpty(username))
            {
                return Unauthorized("Token is missing or invalid.");
            }

            return Ok(new { message = "Token is valid", username, role });
        }
    }
}
