using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Decryption.Algorithms {
    public static class Algorithms {
        public static string CaesarShiftDecryption(string encryptedText, int shift)
        {
            if (encryptedText == null || encryptedText.Equals(string.Empty)) {
                return string.Empty;
            }

            return String.Concat(encryptedText.Select(x => CaesarShiftCharacter(x, shift)));
        }

        public static string XORDecryption(string encryptedText, params byte[] key) {
            if (encryptedText == null || encryptedText.Equals(string.Empty)) {
                return string.Empty;
            }

            if (!IsEncryptedTextValidForXORDecryption(encryptedText)) {
                return Properties.Resources.InvalidInput;
            }

            if (key.Count() == 0) {
                key = new byte[] { 0 };
            }

            return String.Concat(encryptedText.Split(',').Where(x => !x.Equals(string.Empty)).Select((x, i) => (char)(Int32.Parse(x) ^ key[i % key.Length])));
        }

        public static string MonoAlphaDecryption(string encryptedText, IDictionary<char, char> substitutionPairs) {
            if (encryptedText == null || encryptedText.Equals(string.Empty)) {
                return string.Empty;
            }

            return String.Concat(encryptedText.Select(c => {
                if (substitutionPairs.ContainsKey(c)) {
                    return substitutionPairs[c];
                }
                return '?';
            }));
        }

        private static char CaesarShiftCharacter(char character, int shift) {
            if (char.IsUpper(character)) {
                return (char)(((character - 'A' + shift) % 26) + 'A');
            }
            else if (char.IsLower(character)) {
                return (char)(((character - 'a' + shift) % 26) + 'a');
            }

            return character;
        }

        private static bool IsEncryptedTextValidForXORDecryption(string text) {
            return text.All(x => Char.IsDigit(x) || x == ',');
        }
    }
}
