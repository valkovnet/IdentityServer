using System;
using System.Web.Mvc;
using Identity.Membership.Interfaces;

namespace Identity.Membership
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters, IIdentityConfiguration identityConfiguration)
        {
            filters.Add(new HandleErrorAttribute());
            filters.Add(new GlobalViewModelFilter(identityConfiguration));
            filters.Add(new SslRedirectFilter(identityConfiguration.Global.HttpsPort));
        }
    }

    public class GlobalViewModelFilter : ActionFilterAttribute
    {
        private readonly IIdentityConfiguration _identityConfiguration;

        public GlobalViewModelFilter(IIdentityConfiguration identityConfiguration)
        {
            this._identityConfiguration = identityConfiguration;
        }

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            filterContext.Controller.ViewBag.SiteName = this._identityConfiguration.Global.SiteName;
            ////TODO:
            //// filterContext.Controller.ViewBag.IsAdministrator = ClaimsAuthorization.CheckAccess(Constants.Actions.Administration, Constants.Resources.UI);
            filterContext.Controller.ViewBag.IsSignedIn = filterContext.HttpContext.User.Identity.IsAuthenticated;

            base.OnActionExecuting(filterContext);
        }
    }

    public class SslRedirectFilter : ActionFilterAttribute
    {
        private readonly int _port = 443;

        public SslRedirectFilter(int sslPort)
        {
            _port = sslPort;
        }

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (!filterContext.HttpContext.Request.IsSecureConnection)
            {
                filterContext.Result = new RedirectResult(GetAbsoluteUri(filterContext.HttpContext.Request.Url).AbsoluteUri, true);
            }
        }

        private Uri GetAbsoluteUri(Uri uriFromCaller)
        {
            var builder = new UriBuilder(Uri.UriSchemeHttps, uriFromCaller.Host)
            {
                Port = _port,
                Path = uriFromCaller.GetComponents(UriComponents.Path, UriFormat.Unescaped)
            };

            string query = uriFromCaller.GetComponents(UriComponents.Query, UriFormat.UriEscaped);
            if (query.Length > 0)
            {
                string uriWithoutQuery = builder.Uri.AbsoluteUri;
                string absoluteUri = string.Format("{0}?{1}", uriWithoutQuery, query);
                return new Uri(absoluteUri, UriKind.Absolute);
            }

            return builder.Uri;
        }
    }
}