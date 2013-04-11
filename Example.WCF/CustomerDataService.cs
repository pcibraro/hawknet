using System;
using System.Collections.Generic;
using System.Data.Services;
using System.Linq;
using System.ServiceModel.Web;
using System.Text;
using System.Threading;

namespace Example.WCF
{
    public class Customer
    {
        public string ID { get; set; }
        public string Name { get; set; }
    }

    public class CustomerContext
    {
        static List<Customer> AllCustomers = new List<Customer>
        {
            new Customer 
            {
                ID = "1",
                Name = "Foo"
            },
            new Customer
            {
                ID = "2",
                Name = "Bar"
            }
        };

        public IQueryable<Customer> Customers
        {
            get
            {
                return AllCustomers.AsQueryable();
            }
        }
    }
    
    [System.ServiceModel.ServiceBehavior(IncludeExceptionDetailInFaults=true)]
    public class CustomerDataService : DataService<CustomerContext>
    {
        public static void InitializeService(DataServiceConfiguration config)
        {
            config.UseVerboseErrors = true;
            config.SetEntitySetAccessRule("*", EntitySetRights.AllRead);
        }

        
    }
}
