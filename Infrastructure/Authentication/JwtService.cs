using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using drivo_backend.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace drivo_backend.Infrastructure.Authentication;

public class JwtService:IJwtService
{
    private readonly JwtSettings _jwtSettings;

    public JwtService(JwtSettings jwtSettings)
    {
        _jwtSettings=jwtSettings;
    }

    public string GenerateAccessToken(Guid userId,string email,string firstName, string lastName)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub,userId.ToString()),
            new Claim(JwtRegisteredClaimNames.Email,email),
            new Claim(JwtRegisteredClaimNames.GivenName,firstName),
            new Claim(JwtRegisteredClaimNames.FamilyName,lastName),
            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
        };

        var key=new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
        var credentials=new SigningCredentials(key,SecurityAlgorithms.HmacSha256);

        var token=new JwtSecurityToken(
            issuer:_jwtSettings.Issuer,
            audience:_jwtSettings.Audience,
            claims:claims,
            expires:DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpiryMinutes),
            signingCredentials:credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateRefreshToken()
    {
        var randomBytes=new byte[64];
        using var rng=RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    public DateTime GetRefreshTokenExpiryTime()
    {
        return DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays);
    }
}