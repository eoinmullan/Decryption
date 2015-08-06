using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Decryption.Interfaces {
    public interface IDecrypter {
        event EventHandler EncryptionChanged;

        string DecryptText(string encryptedText);
    }
}
