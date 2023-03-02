using Blazored.LocalStorage;
using JWTDemo.Client.Helper;
using JWTDemo.Shared.Models;
using Microsoft.AspNetCore.Components.Authorization;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text;
using JWTDemo.Shared.DTOs;

namespace JWTDemo.Client.Service
{
    public class AuthService : IAuthService
    {
        private readonly HttpClient _httpClient;
        private readonly AuthenticationStateProvider _authenticationStateProvider;
        private readonly ILocalStorageService _localStorage;

        public AuthService(HttpClient httpClient,
                           AuthenticationStateProvider authenticationStateProvider,
                           ILocalStorageService localStorage)
        {
            _httpClient = httpClient;
            _authenticationStateProvider = authenticationStateProvider;
            _localStorage = localStorage;
        }

        public async Task<RegisterResult> Register(RegisterModel registerModel)
        {
            var result = await _httpClient.PostAsJsonAsync("api/accounts/registration", registerModel);
            if (!result.IsSuccessStatusCode)
                return new RegisterResult { Successful = false, Errors = new List<string> { "Error occured" } };
            return new RegisterResult { Successful = true, Errors = new List<string> { "Account Created successfully, Please confirm your E-Maill by click ing the link sent" } };
        }

        public async Task<LoginResult> Login(LoginModel loginModel)
        {
            var loginAsJson = JsonSerializer.Serialize(loginModel);
            var response = await _httpClient.PostAsync("api/login/login",
                new StringContent(loginAsJson, Encoding.UTF8, "application/json"));

            var loginResult = JsonSerializer.Deserialize<LoginResult>(await response.Content.ReadAsStringAsync(),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            //var result = await _httpClient.PostAsJsonAsync("api/Login", loginModel);
            //var response = await result.Content.ReadFromJsonAsync<LoginResult>();

            if (!loginResult!.Successful)
            {
                return new LoginResult { Successful = false, Error = loginResult.Error};
            }

            await _localStorage.SetItemAsync("authToken", loginResult.Token);
            ((ApiAuthenticationStateProvider)_authenticationStateProvider).MarkUserAsAuthenticated(loginResult.Token!);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("bearer", loginResult.Token);

            return new LoginResult { Successful = true };
        }

        public async Task Logout()
        {
            await _localStorage.RemoveItemAsync("authToken");
            ((ApiAuthenticationStateProvider)_authenticationStateProvider).MarkUserAsLoggedOut();
            _httpClient.DefaultRequestHeaders.Authorization = null;
        }

        public async Task<LoginResult> ForgotPassword(ResetPasswordDTO model)
        {
            var result = await _httpClient.PostAsJsonAsync("api/login/forgotPassword", model);

            if (!result.IsSuccessStatusCode)
                return new LoginResult { Successful = false, Error = "Something went wrong!" };
            return new LoginResult { Successful = true, Error = "Password reset link has been sent to your email, please check it out!" };
        }

        public async Task<LoginResult> ResetForgotPassword(ResetPasswordDTO model)
        {
            var result = await _httpClient.PostAsJsonAsync("api/login/ResetForgotPassword", model);
            if (!result.IsSuccessStatusCode)
                return new LoginResult { Successful = false };
            return new LoginResult { Successful = true };
        }
    }
}
