using drivo_backend.Contracts.Auth;
using drivo_backend.Infrastructure.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace drivo_backend.Controllers;

[ApiController]
[Route("/api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IJwtService _jwtService;
    private readonly ILogger<AuthController> _logger;
    private static readonly List<AppUser> _users=new();

    public AuthController(IJwtService jwtService, ILogger<AuthController> logger)
    {
        _jwtService=jwtService;
        _logger=logger;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var user=_users.FirstOrDefault(u=>u.Email.Equals(request.Email,StringComparison.OrdinalIgnoreCase));

        if(user==null || !VerifyPassword(request.Password, user.PasswordHash))
        {
            return Unauthorized(new {message="Invalid email or password"});
        }

        var accessToken=_jwtService.GenerateAccessToken(user.Id,user.Email,user.FirstName,user.LastName);

        var refreshToken=_jwtService.GenerateRefreshToken();
        var refreshTokenExpiry=_jwtService.GetRefreshTokenExpiryTime();

        var response= new AuthResponse
        {
            AccessToken=accessToken,
            RefreshToken=refreshToken,
            TokenType="Bearer",
            ExpiresIn=3600,
            User=new UserDTO
            {
                Id=user.Id,
                FirstName=user.FirstName,
                LastName=user.LastName,
                Email=user.Email,
                PhoneNumber=user.PhoneNumber
            }
        };

        return Ok(response);
    }

    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterRequest request)
    {
        if (request.Password != request.ConfirmPassword)
        {
            return BadRequest(new {message="Passwords do not match"});
        }

        if (_users.Any(u => u.Email.Equals(request.Email, StringComparison.OrdinalIgnoreCase)))
        {
            return Conflict(new {message="Email Already registered"});
        }

        var user =new AppUser
        {
            Id=Guid.NewGuid(),
            FirstName=request.FirstName,
            LastName=request.LastName,
            Email=request.Email,
            PhoneNumber=request.PhoneNumber,
            PasswordHash=HashPassword(request.Password),
            CreatedAt=DateTime.UtcNow
        };

        _users.Add(user);

        return Login(new LoginRequest
        {
            Email=request.Email,
            Password=request.Password
        });
    }

    private string HashPassword(string password)=>BCrypt.Net.BCrypt.HashPassword(password);
    private bool VerifyPassword(string password,string hash)=>BCrypt.Net.BCrypt.Verify(password,hash);


    private class AppUser
    {
        public Guid Id {get;set;}
        public string FirstName {get;set;}=string.Empty;
        public string LastName {get;set;}=string.Empty;
        public string Email {get;set;}=string.Empty;
        public string PhoneNumber {get;set;}=string.Empty;
        public string PasswordHash {get;set;}=string.Empty;
        public DateTime CreatedAt {get;set;}
    }
}
