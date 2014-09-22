using System.Web.Mvc;

namespace Identity.Membership.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {            
            return View();
        }        
    }
}
