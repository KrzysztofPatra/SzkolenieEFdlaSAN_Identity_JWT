using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace CarDealerView.Models
{
    [Table ("CarModels")]
    public class CarModel
    { 
        [Key]
        public int CarModelId { get; set; }

        [Required(ErrorMessage = "Podaj nazwę Producenta")]
        public  string Manufacturer { get; set; }
       
        [Required(ErrorMessage = "Podaj nazwę Modelu")]
        public string Model { get; set; }

        [MaxLength(10, ErrorMessage= "Maksymalnie 10 znaków"), MinLength(1)]
        public string AddInformations { get; set; }

        [NotMapped]
        public string FullModelName { get { return Manufacturer + " " + Model; } }

    }
}
