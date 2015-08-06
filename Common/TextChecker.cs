using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decryption.Interfaces;

namespace Decryption.Common {
    public class TextHelper : ITextHelper {
        public bool ContainsAll(string inputText, params string[] wordsToCheck) {
            return wordsToCheck.All(x => inputText.Contains(x));
        }
    }
}
