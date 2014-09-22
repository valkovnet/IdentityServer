using System;
using System.Collections.ObjectModel;
using System.IdentityModel.Services;
using System.Linq;
using System.Security.Claims;
using System.Web.Mvc;

namespace Identity.Membership.Controllers
{
    public class ClaimsAuthorizeAttribute : AuthorizeAttribute
    {
        private readonly string _action;

        private readonly string[] _resources;

        private const string _label = "Identity.Membership.Core.ClaimsAuthorizeAttribute";

        public ClaimsAuthorizeAttribute()
        { }

        public ClaimsAuthorizeAttribute(string action, params string[] resources)
        {
            _action = action;
            _resources = resources;
        }

        public override void OnAuthorization(System.Web.Mvc.AuthorizationContext filterContext)
        {
            filterContext.HttpContext.Items[_label] = filterContext;
            base.OnAuthorization(filterContext);
        }

        protected override bool AuthorizeCore(System.Web.HttpContextBase httpContext)
        {
            if (!string.IsNullOrWhiteSpace(_action))
            {
                return ClaimsAuthorization.CheckAccess(_action, _resources);
            }

            var filterContext = httpContext.Items[_label] as System.Web.Mvc.AuthorizationContext;
            return CheckAccess(filterContext);
        }

        protected virtual bool CheckAccess(System.Web.Mvc.AuthorizationContext filterContext)
        {
            var action = filterContext.RouteData.Values["action"] as string;
            var controller = filterContext.RouteData.Values["controller"] as string;

            return ClaimsAuthorization.CheckAccess(action, controller);
        }
    }

    public static class ClaimsAuthorization
    {
        public const string ActionType = "http://application/claims/authorization/action";

        public const string ResourceType = "http://application/claims/authorization/resource";

        public static bool EnforceAuthorizationManagerImplementation { get; set; }
       
        public static ClaimsAuthorizationManager AuthorizationManager
        {
            get
            {
                return FederatedAuthentication.FederationConfiguration.IdentityConfiguration.ClaimsAuthorizationManager;
            }
        }

        static ClaimsAuthorization()
        {
            EnforceAuthorizationManagerImplementation = true;
        }
       
        public static bool CheckAccess(string action, params string[] resources)
        {            
            return CheckAccess(ClaimsPrincipal.Current, action, resources);
        }

        public static bool CheckAccess(ClaimsPrincipal principal, string action, params string[] resources)
        {
            var context = CreateAuthorizationContext(principal, action, resources);

            return CheckAccess(context);
        }
      
        public static bool CheckAccess(Collection<Claim> actions, Collection<Claim> resources)
        {           
            return CheckAccess(new System.Security.Claims.AuthorizationContext(ClaimsPrincipal.Current, resources, actions));
        }

        public static bool CheckAccess(string action, params Claim[] resources)
        {
            var actionCollection = new Collection<Claim>();
            actionCollection.Add(new Claim(ActionType, action));
            var resourceCollection = new Collection<Claim>();
            foreach (var resource in resources)
            {
                resourceCollection.Add(resource);
            }

            return CheckAccess(new System.Security.Claims.AuthorizationContext(ClaimsPrincipal.Current, resourceCollection, actionCollection));
        }
        
        public static bool CheckAccess(string action, string resource, params Claim[] resources)
        {            
            var resourceList = resources.ToList();
            resourceList.Add(new Claim(ResourceType, resource));
            return CheckAccess(action, resourceList.ToArray());
        }

        public static bool CheckAccess(System.Security.Claims.AuthorizationContext context)
        {            
            if (EnforceAuthorizationManagerImplementation)
            {
                var authZtype = AuthorizationManager.GetType().FullName;
                if (authZtype != null && authZtype.Equals("System.Security.Claims.ClaimsAuthorizationManager"))
                {
                    throw new InvalidOperationException("No ClaimsAuthorizationManager implementation configured.");
                }
            }

            return AuthorizationManager.CheckAccess(context);
        }

        public static System.Security.Claims.AuthorizationContext CreateAuthorizationContext(ClaimsPrincipal principal, string action, params string[] resources)
        {
            var actionClaims = new Collection<Claim>
                {
                    new Claim(ActionType, action)
                };

            var resourceClaims = new Collection<Claim>();
            if (resources != null && resources.Length > 0)
            {
                resources.ToList().ForEach(ar => resourceClaims.Add(new Claim(ResourceType, ar)));
            }

            return new System.Security.Claims.AuthorizationContext(principal, resourceClaims, actionClaims);
        }
    }
}
