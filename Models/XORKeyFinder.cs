using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decryption.Interfaces;

namespace Decryption.Models {
    internal class XORKeyFinder : IXORKeyFinder {
        private readonly IObservableText encryptedText;
        private readonly ITextHelper textChecker;
        private readonly byte lowerKeyBound;
        private readonly byte upperKeyBound;
        private readonly string[] wordsToFind;

        public XORKeyFinder(IObservableText encryptedText, ITextHelper textChecker, byte lowerKeyBound, byte upperKeyBound, params string[] wordsToFind) {
            this.encryptedText = encryptedText;
            this.textChecker = textChecker;
            this.lowerKeyBound = lowerKeyBound;
            this.upperKeyBound = upperKeyBound;
            this.wordsToFind = wordsToFind;
	    }

        public async Task<byte[]> FindNextKeyAsync(byte[] key, Func<string, string> decrypt, Action<byte[]> updateKeyTried) {
            await Task.Run(() => {
                if (!KeyIsWithinAutoSearchBounds(key)) {
                    return;
                }

                string keyTriedResult;
                do {
                    key = IncrementKey(key);
                    keyTriedResult = decrypt(encryptedText.Text);
                    updateKeyTried(key);
                } while (!textChecker.ContainsAll(keyTriedResult, wordsToFind));
            });

            return key;
        }

        private bool KeyIsWithinAutoSearchBounds(byte[] key) {
            return key.Count() > 0 && key.All(x => x >= lowerKeyBound && x <= upperKeyBound);
        }

        private byte[] IncrementKey(byte[] key) {
            for (var i = key.Count()-1; i >= 0; i--) {
                if (key[i] < upperKeyBound) {
                    key[i]++;
                    break;
                }
                else {
                    key[i] = lowerKeyBound;
                }
            }

            return key;
        }
    }
}
