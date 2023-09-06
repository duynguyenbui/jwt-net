using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Jwt.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Jwt.Controllers;
using BCrypt.Net;

[Route("/api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    public static User user = new User();

    public readonly IConfiguration _configuration;
    
    public AuthController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpPost("Register")]
    public ActionResult<User> Register(UserDto userDto)
    {
        string passwordHash = BCrypt.HashPassword(userDto.Password);
        user.Username = userDto.Username;
        user.PasswordHash = passwordHash;

        return Ok(user);
    }

    [HttpPost("Login")]
    public ActionResult<string> Login(UserDto userDto) 
    {
        if (user.Username != userDto.Username)
        {
            return NotFound("User not found");
        }
        if (!BCrypt.Verify(userDto.Password, user.PasswordHash))
        {
            return BadRequest("Password is not correct");
        }

        string token = createToken(user);
        return Ok(token);
    }

    private string createToken(User user)
    {
        List<Claim> claims = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, user.Username)
        };

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value!));

        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
        var token = new JwtSecurityToken(claims: claims, signingCredentials: creds, expires: DateTime.Now.AddDays(1));

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);
        return jwt;
    }
    
}