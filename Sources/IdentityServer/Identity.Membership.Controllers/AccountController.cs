using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Web.Mvc;
using System.Xml;
using Identity.Membership.Core;
using Identity.Membership.Interfaces;
using Identity.Membership.Models;
using Identity.Membership.Tokens;

namespace Identity.Membership.Controllers
{        
    public class AccountController : Controller
    {
        private readonly IUserRepository _userRepository;

        private readonly IIdentityConfiguration _identityConfiguration;

        public AccountController(IUserRepository userRepository, IIdentityConfiguration identityConfiguration)
        {
            this._userRepository = userRepository;
            this._identityConfiguration = identityConfiguration;
        }

        public ActionResult SignIn(string returnUrl, bool mobile = false)
        {
            var vm = new SignInModel
            {
                ReturnUrl = returnUrl,
                ShowClientCertificateLink = this._identityConfiguration.Global.EnableClientCertificateAuthentication
            };

            if (mobile) vm.IsSigninRequest = true;
            return View(vm);
        }

        public ActionResult SignOut()
        {
            if (Request.IsAuthenticated)
            {
                FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
            }

            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        public ActionResult SignIn(SignInModel model)
        {
            if (ModelState.IsValid)
            {
                if (this._userRepository.ValidateUser(model.UserName, model.Password))
                {                    
                    return SignIn(model.UserName, AuthenticationMethods.Password, model.ReturnUrl, model.EnableSSO, this._identityConfiguration.Global.SsoCookieLifetime);
                }
            }

            ModelState.AddModelError("", "IncorrectCredentialsNoAuthorization");
            model.ShowClientCertificateLink = this._identityConfiguration.Global.EnableClientCertificateAuthentication;
            return View(model);
        }

        private ActionResult SignIn(string userName, string authenticationMethod, string returnUrl, bool isPersistent, int ttl, IEnumerable<Claim> additionalClaims = null)
        {         
            SetSessionToken(userName, authenticationMethod, isPersistent, ttl, additionalClaims);

            if (!string.IsNullOrWhiteSpace(returnUrl))
            {
                return RedirectToLocal(returnUrl);
            }

            return RedirectToAction("Index", "Home");
        }

        public void SetSessionToken(string userName, string authenticationMethod, bool isPersistent, int ttl, IEnumerable<Claim> additionalClaims = null)
        {
            var principal = CreatePrincipal(userName, authenticationMethod, additionalClaims);

            var sessionToken = new SessionSecurityToken(principal, TimeSpan.FromHours(ttl))
            {
                IsPersistent = isPersistent
            };

            FederatedAuthentication.SessionAuthenticationModule.WriteSessionTokenToCookie(sessionToken);
        }

        public ClaimsPrincipal CreatePrincipal(string username, string authenticationMethod, IEnumerable<Claim> additionalClaims = null)
        {
            var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, username),
                        new Claim(ClaimTypes.Name, username),
                        new Claim(ClaimTypes.AuthenticationMethod, authenticationMethod),
                        AuthenticationInstantClaim.Now,
                    };

            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Constants.AuthenticationType));

            // Add additional claims if present
            if (additionalClaims != null)
            {
                additionalClaims.ToList().ForEach(c => principal.Identities.First().AddClaim(c));
            }

            return FederatedAuthentication.FederationConfiguration.IdentityConfiguration.ClaimsAuthenticationManager.Authenticate(string.Empty, principal);
        }
        
        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return RedirectToAction("Index", "Home");
        }
    }

    public static class AuthenticationInstantClaim
    {
        public static Claim Now
        {
            get
            {
                return new Claim(ClaimTypes.AuthenticationInstant, XmlConvert.ToString(DateTime.UtcNow, DateTimeFormats.Generated), ClaimValueTypes.DateTime);
            }
        }
    }
}
