using IdentityServer4.Core.Services.InMemory;
using System.Linq;
using System.Collections.Generic;
using System;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using IdentityModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using System.Threading.Tasks;

namespace Host.UI.Login
{
    public class LoginService
    {
        private readonly UserManager<IdentityUser> _userManager;

        public LoginService(UserManager<IdentityUser> signInManager)
        {
            _userManager = signInManager;
        }

        public async Task<bool> ValidateCredentials(string username, string password)
        {
            var user = await _userManager.FindByNameAsync(username);

            return user == null ? false : true;
        }

        public async Task<IdentityUser> FindByUsername(string username)
        {
            return await _userManager.FindByNameAsync(username);
        }
    }
}
