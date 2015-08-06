using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Decryption.Interfaces {
    public interface IXORDecrypter : IDecrypter {
        event EventHandler KeyChanged;

        byte[] Key { get; set; }

        void FindKey(byte lowerBound, byte upperBound, params string[] wordsToFind);
    }
}
