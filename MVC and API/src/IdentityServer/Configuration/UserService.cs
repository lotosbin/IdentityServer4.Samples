using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Core.Extensions;
using IdentityServer4.Core.Models;
using IdentityServer4.Core.Services;
using IdentityServer4.Core.Validation;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Host.Configuration
{
    public class IdentityProfileService : IProfileService
    {
        private readonly UserManager<IdentityUser> _userManager;
        public IdentityProfileService(UserManager<IdentityUser> userManager){
            _userManager= userManager;
        }
        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var userId = context.Subject.GetSubjectId();
            var user =  _userManager.FindByIdAsync(userId);

            var claims = new List<Claim>{
                new Claim(JwtClaimTypes.Subject, user.Id.ToString()),
            };

            // claims.AddRange(user.Claims);
            // if (!context.AllClaimsRequested)
            // {
            //     claims = claims.Where(x => context.RequestedClaimTypes.Contains(x.Type)).ToList();
            // }

            context.IssuedClaims = claims;

            return Task.FromResult(0);
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            var userId = context.Subject.GetSubjectId();
            var user =  _userManager.FindByIdAsync(userId);
            context.IsActive = (user != null);
            return  Task.FromResult(0);
        }
    }
    public class IdentityResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        public IdentityResourceOwnerPasswordValidator(SignInManager<IdentityUser> signInManager){
            _signInManager= signInManager;
        }   
        public Task<CustomGrantValidationResult> ValidateAsync(string userName, string password, ValidatedTokenRequest request)
        {
            var user =  _signInManager.PasswordSignInAsync(userName, password, true, lockoutOnFailure: false);
            if (user != null)
            {
                return Task.FromResult(new CustomGrantValidationResult(user.Id.ToString(), "password"));
            }

            return Task.FromResult(new CustomGrantValidationResult("Invalid username or password"));
        }
    }
    public class ApplicationDbContext : IdentityDbContext<IdentityUser>
    {
        public ApplicationDbContext(DbContextOptions options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);
        }
    }
}
