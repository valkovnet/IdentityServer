using System;
using System.IdentityModel.Services;
using System.Web.Mvc;

namespace IdentityClient.Controllers
{
    [Authorize]    
    public class AccountController : Controller
    {        
        public ActionResult Index()
        {
            return View("Identity", HttpContext.User);
        }

        public ActionResult Signout()
        {
            var fam = FederatedAuthentication.WSFederationAuthenticationModule;
            fam.SignOut(false);

            var signOutRequest = new SignOutRequestMessage(new Uri(fam.Issuer), fam.Realm) { Reply = fam.Reply };
            return new RedirectResult(signOutRequest.WriteQueryString());
        }

    }
}
