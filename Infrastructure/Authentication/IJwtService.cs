namespace drivo_backend.Infrastructure.Authentication;

public interface IJwtService
{
    string GenerateAccessToken(Guid userId, string email, string firstName, string lastName);
    string GenerateRefreshToken();
    DateTime GetRefreshTokenExpiryTime();
}