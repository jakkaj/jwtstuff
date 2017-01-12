using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JwtHelpers;
using System.IdentityModel.Protocols.WSTrust;

namespace JwtSamples
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Nope!");
                return;
            }

            var ar = args[0];


            //get a public and private key set. 
            if (ar == "generate")
            {
                var keys = Generator.GenerateRsaKeys();

                var pub = Convert.ToBase64String(Encoding.UTF8.GetBytes(keys.PublicKeyOnly));
                var pri = Convert.ToBase64String(Encoding.UTF8.GetBytes(keys.PublicAndPrivateKey));

                File.WriteAllText("publickey.txt", pub);
                File.WriteAllText("privatekey.txt", pri);

                Console.WriteLine($"Private: {pri}");
                Console.WriteLine($"Public: {pub}");
            }
            else
            {
                if (!File.Exists("privatekey.txt"))
                {
                    Console.WriteLine("Please run generate first");
                    return;
                }

                var pub = File.ReadAllText("publickey.txt");
                var pri = File.ReadAllText("privatekey.txt");

                var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier,"Some user id"),
                new Claim("customClaim", "some custom claim")
            };

                var claimsId = new ClaimsIdentity(claims.ToArray());

                var now = DateTime.Now;

                var token = JwtCreator.CreateToken(claimsId, "SomeIssuer", "Someaudience", now.AddMinutes(-60), now.AddDays(7), pri);

                Console.WriteLine(token);

                var validated = Validator.ValidateWithRsaKey(token, pub, "SomeIssuer", "Someaudience");

                Console.WriteLine(validated.IsValid);


            }
            Console.ReadLine();
        }
    }
}
