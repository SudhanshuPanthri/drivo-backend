using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("/api/[controller]")]
[Authorize]
public class ProtectedController : ControllerBase
{
    [HttpGet("me")]
    public IActionResult GetCurrentUser()
    {
        var userId=User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email=User.FindFirst(ClaimTypes.Email)?.Value;

        return Ok(new {userId,email,message="AUthenticated User"});
    }
}