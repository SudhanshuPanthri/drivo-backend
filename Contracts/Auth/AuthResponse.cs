namespace drivo_backend.Contracts.Auth;

class AuthResponse
{
    public string AccessToken {get;set;}=string.Empty;
    public string RefreshToken {get;set;}=string.Empty;
    public string TokenType {get;set;}="Bearer";
    public int ExpiresIn {get;set;}
    public UserDTO User {get;set;}=null!;
}

public class UserDTO
{
    public Guid Id {get;set;}
    public string FirstName {get;set;}=string.Empty;
    public string LastName {get;set;}=string.Empty;
    public string Email {get;set;}=string.Empty;
    public string PhoneNumber {get;set;}=string.Empty;
}