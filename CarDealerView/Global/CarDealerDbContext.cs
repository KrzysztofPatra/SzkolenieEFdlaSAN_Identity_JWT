using IdentitySample.Models.AccountViewModels;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CarDealerView.Models
{
    public class CarDealerDbContext: IdentityDbContext<ApplicationUser>
    {

        public CarDealerDbContext(DbContextOptions<CarDealerDbContext> options)
       : base(options)
        { }


        public DbSet<Car> Cars { get; set; }
        public DbSet<CarModel> CarModels { get; set; }


    }
}
