using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Globalization;
using System.Text.RegularExpressions;
using Decryption.Common;
using Decryption.Interfaces;
using Decryption.ViewModels;

namespace Decryption.Models {
    internal class XORDecrypter : DecrypterBase, IXORDecrypter {
        public event EventHandler KeyChanged;
        private readonly IObservableText encryptedText;
        private readonly ITextHelper textHelper;
        private readonly IXORKeyFinderFactory xorKeyFinderFactory;

        private byte LowerKeyBound { get; set; }
        private byte UpperKeyBound { get; set; }

        private byte[] key;
        public byte[] Key {
            get {
                return key;
            }
            set {
                key = value;

                RaiseKeyChanged();
                RaiseEncryptionChanged();
            }
        }

        public XORDecrypter(
            IObservableText encryptedText,
            ITextHelper textChecker,
            IXORKeyFinderFactory xorKeyFinderFactory,
            params byte[] key) {
            this.encryptedText = encryptedText;
            this.textHelper = textChecker;
            this.xorKeyFinderFactory = xorKeyFinderFactory;
            Key = key;
        }

        public override string DecryptText(string encryptedText) {
            return Algorithms.Algorithms.XORDecryption(encryptedText, key);
        }

        public override string ToString() {
            return "XOR";
        }

        public async void FindKey(byte lowerBound, byte upperBound, params string[] wordsToFind) {
            var xorKeyFinder = xorKeyFinderFactory.Create(encryptedText, textHelper, lowerBound, upperBound, wordsToFind);
            Key = await xorKeyFinder.FindNextKeyAsync(key, DecryptText, x => Key = x);
        }

        private void RaiseKeyChanged() {
            if (KeyChanged != null) {
                KeyChanged(this, new EventArgs());
            }
        }
    }
}
