using System.IdentityModel.Services;
using System.Security.Claims;
using System.Web.Mvc;
using Identity.Membership.Core.WSTrust;
using Identity.Membership.Types;

namespace Identity.Membership.Controllers
{
    [ClaimsAuthorize("Issue", "WSTrust")]
    public class WSFederationController : Controller
    {        
        public ActionResult Issue()
        {
            WSFederationMessage message = WSFederationMessage.CreateFromUri(HttpContext.Request.Url);

            // Sign in 
            var signinMessage = message as SignInRequestMessage;
            if (signinMessage != null)
            {
                return ProcessWSFederationSignIn(signinMessage);
            }

            // Sign out
            var signoutMessage = message as SignOutRequestMessage;
            if (signoutMessage != null)
            {
                return ProcessWSFederationSignOut(signoutMessage);
            }

            return View("Error");
        }

        private ActionResult ProcessWSFederationSignIn(SignInRequestMessage message)
        {
            SignInResponseMessage response = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(message, ClaimsPrincipal.Current, TokenServiceConfiguration.Instance.CreateSecurityTokenService());
            
            var sessionManager = new SignInSessionsManager(HttpContext);
            sessionManager.AddEndpoint(response.BaseUri.AbsoluteUri);

            return new WSFederationResult(response, true);
        }

        private ActionResult ProcessWSFederationSignOut(SignOutRequestMessage message)
        {
            FederatedAuthentication.SessionAuthenticationModule.SignOut();
            if (!string.IsNullOrWhiteSpace(message.Reply))
            {
                ViewBag.ReturnUrl = message.Reply;
            }
            
            var mgr = new SignInSessionsManager(HttpContext);
            var realms = mgr.GetEndpoints();
            mgr.ClearEndpoints();

            return View("Signout", realms);
        }
    }
}
