
using JWTDemo.Server.DTOs;
using JWTDemo.Shared.DTOs;
using JWTDemo.Shared.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTDemo.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailService _emailService;
        public LoginController(IConfiguration configuration, SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager, IEmailService emailService)
        {
            _configuration = configuration;
            _signInManager = signInManager;
            _userManager = userManager;
            _emailService = emailService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            var result = await _signInManager.PasswordSignInAsync(login.Email!, login.Password!, false, false);

            if (!result.Succeeded) return BadRequest(new LoginResult { Successful = false, Error = "Username and password are invalid." });

            var user = await _signInManager.UserManager.FindByEmailAsync(login.Email!);
            var roles = await _signInManager.UserManager.GetRolesAsync(user!);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, login.Email!)
            };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSecurityKey"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expiry = DateTime.Now.AddDays(Convert.ToInt32(_configuration["JwtExpiryInDays"]));

            var token = new JwtSecurityToken(
                _configuration["JwtIssuer"],
                _configuration["JwtAudience"],
                claims,
                expires: expiry,
                signingCredentials: creds
            );

            return Ok(new LoginResult { Successful = true, Token = new JwtSecurityTokenHandler().WriteToken(token) });
        
        }


        [HttpPost("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword(ResetPasswordDTO model)
        {
            if(string.IsNullOrEmpty(model.Email))
            {
                return BadRequest();
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if(user != null)
            {
                var ResetPasswordToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                var encodeResetPasswordToken = Encoding.UTF8.GetBytes(ResetPasswordToken);
                var validResetPasswordToken = WebEncoders.Base64UrlEncode(encodeResetPasswordToken);
                string url = $"{_configuration["AppUrl"]}/ResetForgotPassword?email={user.Email}&token={validResetPasswordToken}";

                var requestDto = new RequestDTO
                {
                    To = user.Email!,
                    Subject = "Confirm Account to Reset",
                    Message = $"<p>Welcome to Netcode-Hub Site</p> <p>Please reset your account password by clicking on this button <a href='{url}'>Click here</a></p>"
                };
                var retunText = await _emailService.SendEmail(requestDto);
                if (retunText.Contains("Mail Sent!"))
                {
                    return Ok(new LoginResult { Successful = true });
                }
            }
            return NotFound();
        }


        [HttpPost("ResetForgotPassword")]
        public async Task<IActionResult> ResetForgotPassword(ResetPasswordDTO model)
        {
            if (string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Token))
            {
                return BadRequest();
            }
            var user = await _userManager.FindByEmailAsync(model.Email!);
            if (user != null)
            {
                var decodedToken = WebEncoders.Base64UrlDecode(model.Token);
                string normalToken = Encoding.UTF8.GetString(decodedToken);
                var result = await _userManager.ResetPasswordAsync(user, normalToken, model.NewPassword!);
                if (result.Succeeded)
                {
                    return Redirect($"{_configuration["AppUrl"]}/login"!);
                }
                return BadRequest();
            }
            return BadRequest();
        }
    }
}
