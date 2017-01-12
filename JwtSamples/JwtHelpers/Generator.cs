using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace JwtHelpers
{
    public static class Generator
    {
        public static RsaKeyGenerationResult GenerateRsaKeys()
        {
            var myRSA = new RSACryptoServiceProvider(2048);
            var publicKey = myRSA.ExportParameters(true);
            var result = new RsaKeyGenerationResult();
            result.PublicAndPrivateKey = myRSA.ToXmlString(true);
            result.PublicKeyOnly = myRSA.ToXmlString(false);
            return result;
        }

        public class RsaKeyGenerationResult
        {
            public string PublicKeyOnly { get; set; }
            public string PublicAndPrivateKey { get; set; }
        }
    }
}
