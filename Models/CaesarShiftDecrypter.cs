using System;
using System.Collections.Generic;
using System.Linq;
using System.ComponentModel;
using System.Text;
using System.Threading.Tasks;
using Decryption.Interfaces;
using DecryptionFs;

namespace Decryption.Models {
    internal class CaesarShiftDecrypter : DecrypterBase, ICaesarShiftDecrypter {
        private int shift;
        public int Shift {
            get {
                return shift;
            }
            set {
                shift = value;
                RaiseEncryptionChanged();
            }
        }

        public CaesarShiftDecrypter() : this(0) { 
        }

        public CaesarShiftDecrypter(int key) {
            Shift = key;
        }

        public override string DecryptText(string encryptedText) {
            return AlgorithmsFs.CaesarShiftDecryption(encryptedText, Shift);
        }

        public override string ToString() {
            return "Caesar";
        }
    }
}
