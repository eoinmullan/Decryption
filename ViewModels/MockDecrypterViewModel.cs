using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decryption.Interfaces;
using Decryption.Models;

namespace Decryption.ViewModels {
    internal class MockDecrypterViewModel {
        private List<IDecrypter> decrypters;
        public List<IDecrypter> Decrypters {
            get {
                return decrypters;
            }
        }

        private IDecrypter monoAlphaDecrypter;
        private IDecryptionSetupViewModel monoAlphaDecrypterViewModel;
        public IDecryptionSetupViewModel CurrentDecrypterViewModel {
            get {
                return monoAlphaDecrypterViewModel;
            }
            set { }
        }

        public MockDecrypterViewModel() {
            monoAlphaDecrypter = new MonoAlphaDecrypter();
            monoAlphaDecrypterViewModel = new MonoAlphaSetupViewModel(monoAlphaDecrypter, null);
            decrypters = new List<IDecrypter>() {
                new CaesarShiftDecrypter(),
                new XORDecrypter(null, null, null),
                monoAlphaDecrypter
            };
        }
    }
}
