using JWTDemo.Shared.DTOs;

namespace JWTDemo.Server.DTOs
{
    public interface IEmailService
    {
        Task<string> SendEmail(RequestDTO request);
    }
}
