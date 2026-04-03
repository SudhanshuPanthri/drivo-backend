using drivo_backend.Configuration;
using drivo_backend.Contracts.Auth;
using drivo_backend.Domain.Entities;
using drivo_backend.Infrastructure.Authentication;
using drivo_backend.Infrastructure.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace drivo_backend.Controllers;

[ApiController]
[Route("/api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IJwtService _jwtService;
    private readonly ILogger<AuthController> _logger;
    private readonly AppDbContext _dbContext;
    private readonly JwtSettings _jwtSettings;

    public AuthController(IJwtService jwtService, ILogger<AuthController> logger, AppDbContext dbContext, JwtSettings jwtSettings)
    {
        _jwtService=jwtService;
        _logger=logger;
        _dbContext=dbContext;
        _jwtSettings=jwtSettings;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user=await _dbContext.Users.FirstOrDefaultAsync(u=>u.Email.ToLower()==request.Email.ToLower());

        if(user==null || !VerifyPassword(request.Password, user.PasswordHash))
        {
            return Unauthorized(new {message="Invalid email or password"});
        }

        var accessToken=_jwtService.GenerateAccessToken(user.Id,user.Email,user.FirstName,user.LastName);

        var refreshToken=_jwtService.GenerateRefreshToken();
        var refreshTokenExpiry=_jwtService.GetRefreshTokenExpiryTime();

        _dbContext.RefreshTokens.Add(new RefreshToken
        {
            Id=Guid.NewGuid(),
            Token=refreshToken,
            UserId=user.Id,
            ExpiresAt=refreshTokenExpiry,
            CreatedAt=DateTime.UtcNow
        });
        await _dbContext.SaveChangesAsync();

        var response= new AuthResponse
        {
            AccessToken=accessToken,
            RefreshToken=refreshToken,
            TokenType="Bearer",
            ExpiresIn=_jwtSettings.AccessTokenExpiryMinutes,
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
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (request.Password != request.ConfirmPassword)
        {
            return BadRequest(new {message="Passwords do not match"});
        }

        if (await _dbContext.Users.AnyAsync(u => u.Email.ToLower()==request.Email.ToLower()))
        {
            return Conflict(new {message="Email Already registered"});
        }

        var user =new User
        {
            Id=Guid.NewGuid(),
            FirstName=request.FirstName,
            LastName=request.LastName,
            Email=request.Email,
            PhoneNumber=request.PhoneNumber,
            PasswordHash=HashPassword(request.Password),
            CreatedAt=DateTime.UtcNow
        };

        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();

        return await Login(new LoginRequest
        {
            Email=request.Email,
            Password=request.Password
        });

    }

    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        var refreshToken=await _dbContext.RefreshTokens.Include(rt=>rt.User).FirstOrDefaultAsync(rt=>rt.Token==request.RefreshToken);

        if(refreshToken==null || !refreshToken.IsActive)
        {
            return Unauthorized(new {message="Invalid refresh Token"});
        }

        refreshToken.RevokedAt=DateTime.UtcNow;

        var newAccessToken=_jwtService.GenerateAccessToken(refreshToken.User.Id,refreshToken.User.Email,refreshToken.User.FirstName,refreshToken.User.LastName);

        var newRefreshToken=_jwtService.GenerateRefreshToken();
        var newRefreshTokenExpiryTime=_jwtService.GetRefreshTokenExpiryTime();

        _dbContext.RefreshTokens.Add(new RefreshToken
        {
            Id = Guid.NewGuid(),
            Token = newRefreshToken,
            UserId = refreshToken.User.Id,
            ExpiresAt = newRefreshTokenExpiryTime,
            CreatedAt = DateTime.UtcNow
        });

        await _dbContext.SaveChangesAsync();

        return Ok(new AuthResponse
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            TokenType = "Bearer",
            ExpiresIn = 3600,
            User = new UserDTO
            {
                Id = refreshToken.User.Id,
                FirstName = refreshToken.User.FirstName,
                LastName = refreshToken.User.LastName,
                Email = refreshToken.User.Email,
                PhoneNumber = refreshToken.User.PhoneNumber
            }
        });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
    {
        var refreshToken=await _dbContext.RefreshTokens.FirstOrDefaultAsync(x=>x.Token==request.RefreshToken);

        if (refreshToken != null)
        {
            refreshToken.RevokedAt=DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();
        }

        return Ok(new {message="Logged out successfully"});
    }
    
    private string HashPassword(string password)=>BCrypt.Net.BCrypt.HashPassword(password);
    private bool VerifyPassword(string password,string hash)=>BCrypt.Net.BCrypt.Verify(password,hash);

}
