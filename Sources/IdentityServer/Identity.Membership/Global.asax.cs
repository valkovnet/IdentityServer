using System.Security.Claims;
using System.Web.Helpers;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using Identity.Membership.Configurations;
using Identity.Membership.Interfaces;
using Identity.Membership.Repositories;
using SimpleInjector;
using SimpleInjector.Integration.Web.Mvc;
using GlobalConfiguration = System.Web.Http.GlobalConfiguration;

namespace Identity.Membership
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();

            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.Name;
            SetupCompositionContainer();

            GlobalConfiguration.Configuration.MessageHandlers.Add(new RequireHttpsHandler());          

            var configuration = new IdentityIdentityConfiguration();

            WebApiConfig.Register(GlobalConfiguration.Configuration);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters, configuration);
            RouteConfig.RegisterRoutes(RouteTable.Routes);            
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }

        private void SetupCompositionContainer()
        {
            var container = new Container();
            container.RegisterPerWebRequest<IUserRepository, ProviderUserRepository>();
            container.RegisterSingle<IIdentityConfiguration, IdentityIdentityConfiguration>();
            container.RegisterSingle<IRelyingPartyRepository, RelyingPartyRepository>();
            
            container.Verify();
            DependencyResolver.SetResolver(new SimpleInjectorDependencyResolver(container));
        }
    }
}