using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace CarDealerView.Models
{
    [Table("Cars")]
    public class Car
    {
        [Key]
        public int CarId { get; set; }

        [Required(ErrorMessage = "Podaj rok produkcj")]
        public int ProductionYear { get; set; }
        public int Mileage { get; set; }
        public bool AccidentFree { get; set; }
        public double Price { get; set; }
        public double Discount { get; set; }

        [ForeignKey("CarModels")]   
        // w bazie chcę mieśc powiązanie między tabelkami stąd dodadaję, stąd podaję klucz obcy do tabeli oraz  polę typu Virtual po to aby wskazać referncję do danej tabeli.
        public int CarModelId { get; set; }
        public virtual CarModel CarModels { get; set; }
    }
}
