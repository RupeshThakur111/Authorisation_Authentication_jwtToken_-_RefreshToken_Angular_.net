using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using AngularAuthAPI.Models.dto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext appDbContext)
        {
             _authContext = appDbContext;
        }

        // for normal jwt token 
        //[HttpPost("authenticate")]
        //public async Task<IActionResult> Authenticate([FromBody] UserLoginModel LogIn)
        //{
        //    if (LogIn == null)
        //        return BadRequest();
        //    User userObj = ConvertLoginModelToDbModel(LogIn);
        //    var user = await _authContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName);

        //    if (user == null)
        //    {
        //        return NotFound(new { Message = "User Not Found!" });
        //    }
        //    if(!PasswordHasher.VerifyPassword(userObj.Password , user.Password))
        //    {
        //        return BadRequest(new 
        //        { Message = "password is Incorrect" });
        //    }

        //    user.Token = CreateJwtToken(user);

        //    return Ok(new 
        //    {
        //        Token = user.Token,
        //        Message = "Login Success" 
        //    });   

        //}


                                                       //  for Refresh Token

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] UserLoginModel LogIn)
        {
            if (LogIn == null)
                return BadRequest();
            User userObj = ConvertLoginModelToDbModel(LogIn);
            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName);

            if (user == null)
            {
                return NotFound(new { Message = "User Not Found!" });
            }
            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new
                { Message = "password is Incorrect" });
            }

            user.Token = CreateJwtToken(user);

            var newAccessToken = user.Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(5);
            await _authContext.SaveChangesAsync();

            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken= newRefreshToken
            });

        }

        [HttpPost("registerUser")]
        public async Task<IActionResult> RegisterUserAsUser([FromBody] UserSignupModel signUP)
        {
            if(signUP == null)
            {
                return BadRequest();
            }

            User userObj = ConvertsignUpModelToDbModel(signUP);

            //checking is user name is unique
            if(await CheckUserNameExistsAsync(userObj.UserName))
            {
                return BadRequest(new {Message = "user name already exists"});
            }

            // checking if email is unique
            if (await CheckEmailExistsAsync(userObj.Email))
            {
                return BadRequest(new { Message = "email  already exists" });
            }

            // checking password strength
            var pass = CheckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(pass))
            {
                return BadRequest(new { Message = pass.ToString() });
            }

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new { Message = "User Registered!" });
        }

        [HttpPost("registerAdmin")]
        public async Task<IActionResult> RegisterUserAsAdmin([FromBody] UserSignupModel signUP)
        {
            if (signUP == null)
            {
                return BadRequest();
            }

            User userObj = ConvertsignUpModelToDbModel(signUP);

            //checking is user name is unique
            if (await CheckUserNameExistsAsync(userObj.UserName))
            {
                return BadRequest(new { Message = "admin name already exists" });
            }

            // checking if email is unique
            if (await CheckEmailExistsAsync(userObj.Email))
            {
                return BadRequest(new { Message = "email  already exists" });
            }

            // checking password strength
            var pass = CheckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(pass))
            {
                return BadRequest(new { Message = pass.ToString() });
            }

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "Admin";
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new { Message = "Admin Registered!" });
        }
        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var key = Encoding.UTF8.GetBytes("veryverysecret.....");
            var tokenValidationParameters = new TokenValidationParameters 
            {
             ValidateAudience = false,
             ValidateIssuer = false,
             ValidateIssuerSigningKey = true,
             IssuerSigningKey = new SymmetricSecurityKey(key),
             ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if(jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase)) 
            {
                throw new SecurityTokenException("This is Invalid Token");
            }
            return principal;
        }

        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUser()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }

        [HttpPost ("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDto tokenApiDto)
        {
            if(tokenApiDto is null)
            {
                return BadRequest("Invalid Client Request");
            }
            string accessToken = tokenApiDto.AccessToken;
            string refreshToken = tokenApiDto.RefreshToken;
            var principal = GetPrincipalFromExpiredToken(accessToken);
            var username = principal.Identity.Name;
            var user = await _authContext.Users.FirstOrDefaultAsync(u => u.UserName == username);
            if(user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid Request");
            }
            var newAccessToken = CreateJwtToken(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _authContext.SaveChangesAsync();
            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
            });
        }
        private static User ConvertsignUpModelToDbModel(UserSignupModel userSignUp)
        {
            User userObj = new User()
            {
                FirstName = userSignUp.FirstName,
                LastName = userSignUp.LastName,
                Email = userSignUp.Email,
                UserName = userSignUp.UserName,
                Password = userSignUp.Password,
            };
            return userObj;
        }

        private static User ConvertLoginModelToDbModel(UserLoginModel userLogin)
        {
            User userObj = new User()
            {
                UserName = userLogin.UserName,
                Password = userLogin.Password,
            };
            return userObj;
        }

        private async Task<bool> CheckUserNameExistsAsync(string userName)
        {
            return await _authContext.Users.AnyAsync(x => x.UserName == userName);

        }

        private async Task<bool> CheckEmailExistsAsync(string email)
        {
            return await _authContext.Users.AnyAsync(x => x.Email == email);

        }

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if(password.Length < 8)
                sb.Append("Minimum password length should be 8" + Environment.NewLine);
            
            if (!(Regex.IsMatch(password, "[a-z]")&& Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be alpha numeric" + Environment.NewLine);
            
            if (!Regex.IsMatch(password, "[!,@,#,$,%,^,&,*,/,{,},=,+,-]"))
                sb.Append("Password should contain special character" + Environment.NewLine);
            
            return sb.ToString();
        }

        private string CreateJwtToken(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysecret.....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role,user.Role),
               // new Claim(ClaimTypes.Name , $"{user.FirstName} {user.LastName}")   -->> for jwt token
               new Claim(ClaimTypes.Name,$"{user.UserName}")  // ==>> for refresh token
            });
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(10),
                SigningCredentials = credentials
            };
            var jwtToken = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(jwtToken);
        }

        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);

            var tokenInUser = _authContext.Users.Any(a => a.RefreshToken == refreshToken);

            if (tokenInUser)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }
    }
}
