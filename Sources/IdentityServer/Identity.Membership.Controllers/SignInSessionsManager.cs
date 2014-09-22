using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Identity.Membership.Controllers
{
    public class SignInSessionsManager
    {
        private readonly string _cookieName;

        private readonly HttpContextBase _context;

        private int _maximumCookieLifetime;

        public SignInSessionsManager(HttpContextBase context, string cookieName = "wsfed", int maximumCookieLifetime = 24)
        {
            this._context = context;
            this._cookieName = cookieName;
            this._maximumCookieLifetime = maximumCookieLifetime;
        }

        public void AddEndpoint(string address)
        {
            var endpoints = ReadCookie();
            if (!endpoints.Contains(address))
            {
                endpoints.Add(address);
                WriteCookie(endpoints);
            }
        }

        public void SetEndpoint(string address)
        {
            ClearEndpoints();
            WriteCookie(new List<string> { address });
        }

        public List<string> GetEndpoints()
        {
            return ReadCookie();
        }

        public void ClearEndpoints()
        {
            var cookie = _context.Request.Cookies[_cookieName];
            if (cookie != null)
            {
                cookie.Value = "";
                cookie.Expires = new DateTime(2000, 1, 1);
                cookie.Path = HttpRuntime.AppDomainAppVirtualPath;

                _context.Response.SetCookie(cookie);
            }
        }

        private List<string> ReadCookie()
        {
            var cookie = _context.Request.Cookies[_cookieName];
            if (cookie == null)
            {
                return new List<string>();
            }

            return cookie.Value.Split('|').ToList();
        }

        private void WriteCookie(List<string> realms)
        {
            if (realms.Count == 0)
            {
                ClearEndpoints();
                return;
            }

            var realmString = string.Join("|", realms);

            var cookie = new HttpCookie(_cookieName, realmString)
            {
                Secure = true,
                HttpOnly = true,
                Path = HttpRuntime.AppDomainAppVirtualPath
            };

            _context.Response.Cookies.Add(cookie);
        }
    }
}
