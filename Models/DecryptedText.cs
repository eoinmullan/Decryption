using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decryption.Common;
using Decryption.Interfaces;

namespace Decryption.Models {
    internal class DecryptedText : ObservableText, IDecryptedText {
        private IObservableText encryptedText;

        private IDecrypter currentDecrypter;
        public IDecrypter CurrentDecrypter {
            get {
                return currentDecrypter;
            }
            set {
                currentDecrypter = value;
                currentDecrypter.EncryptionChanged += HandleEncryptedTextChanged;
                UpdateDecryptedText();
            }
        }

        public DecryptedText(IObservableText encryptedText) {
            this.encryptedText = encryptedText;
            encryptedText.TextChanged += HandleEncryptedTextChanged;
        }

        void HandleEncryptedTextChanged(object sender, EventArgs e) {
            UpdateDecryptedText();
        }

        private void UpdateDecryptedText() {
            Text = CurrentDecrypter.DecryptText(encryptedText.Text);
        }
    }
}
