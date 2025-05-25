namespace AuthServiceAPI.Models;

public class ValidatedUserResponse
{
    
    public string Username { get; set; }
    public string EmailAdress { get; set; }
    public string Password { get; set; }
    public string? Role { get; set; }
}