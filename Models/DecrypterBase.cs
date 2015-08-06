using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decryption.Interfaces;

namespace Decryption.Models {
    internal abstract class DecrypterBase : IDecrypter {
        public event EventHandler EncryptionChanged;

        public abstract string DecryptText(string encryptedText);

        protected void RaiseEncryptionChanged() {
            if (EncryptionChanged != null) {
                EncryptionChanged(this, new EventArgs());
            }
        }
    }
}
