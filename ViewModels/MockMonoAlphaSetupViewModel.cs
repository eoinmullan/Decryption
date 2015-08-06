using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using Decryption.Interfaces;

namespace Decryption.ViewModels {
    internal class MockMonoAlphaSetupViewModel : IDecryptionSetupViewModel {
        private string encryptedText = "BBBBAAACCD";

        public string Name {
            get {
                return "Mono alpha sub";
            }
        }

        public IDictionary<char, double> InputCharacterSet {
            get {
                return encryptedText
                    .Distinct()
                    .Select(x => new {
                        character = x,
                        frequency = (encryptedText.Count(y => y == x) / (double)encryptedText.Count()) * 100
                    })
                    .OrderByDescending(x => x.frequency)
                    .ToDictionary(x => x.character, x => x.frequency);
            }
        }
    }
}
