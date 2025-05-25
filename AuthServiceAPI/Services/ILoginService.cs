using AuthServiceAPI.Models;

namespace AuthServiceAPI.Services;

public interface ILoginService
{
    Task<string?> AuthenticateAsync(Login login);
}