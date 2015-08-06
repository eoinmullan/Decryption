using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decryption.Models;

namespace Decryption.Models {
    internal class MonoAlphaDecrypter : DecrypterBase {
        IDictionary<char, char> pairs;

        public MonoAlphaDecrypter() {
            pairs = new Dictionary<char, char> { { ' ', ' ' } };
        }

        public void LoadSubstitutionPair(char find, char replace) {
            if (pairs.ContainsKey(find)) {
                pairs[find] = replace;
            }
            else {
                pairs.Add(find, replace);
            }

            RaiseEncryptionChanged();
        }

        public override string DecryptText(string encryptedText) {
            return Algorithms.Algorithms.MonoAlphaDecryption(encryptedText, pairs);
        }

        public override string ToString() {
            return "MonoAlpha";
        }
    }
}
