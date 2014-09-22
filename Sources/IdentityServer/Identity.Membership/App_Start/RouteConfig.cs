using System.ServiceModel.Activation;
using System.Web.Mvc;
using System.Web.Routing;
using Identity.Membership.Core.WSTrust;

namespace Identity.Membership
{
    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");
            
            routes.MapRoute(
                "Account",
                "account/{action}",
                new {controller = "Account", action = "Index", id = UrlParameter.Optional});

            routes.MapRoute(
                "Home",
                "{action}",
                new {controller = "Home", action = "Index", id = UrlParameter.Optional},
                new [] { "Identity.Membership.Controllers" });

            routes.MapRoute("wsfederation",
                    "issue/wsfed",
                    new { controller = "WSFederation", action = "issue" }
                 );

            routes.Add(new ServiceRoute("issue/wstrust", new TokenServiceHostFactory(), typeof(TokenServiceConfiguration)));
        }
    }
}