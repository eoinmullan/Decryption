using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Decryption.Interfaces {
    public interface ITextHelper {
        bool ContainsAll(string inputText, params string[] wordsToCheck);
    }
}
