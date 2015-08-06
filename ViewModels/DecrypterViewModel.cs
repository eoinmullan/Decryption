using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decryption.Interfaces;
using System.ComponentModel;
using System.Windows.Data;
using Decryption;
using Decryption.Common;

namespace Decryption.ViewModels {
    internal class DecrypterViewModel : ModelBase {
        private IObservableText encryptedText;
        private IDecryptedText decryptedText;
        public string EncryptedText {
            get {
                return encryptedText.Text;
            }
            set {
                encryptedText.Text = value;
                OnPropertyChanged("EncryptedText");
            }
        }

        public string DecryptedText {
            get {
                return decryptedText.Text;
            }
        }

        public List<IDecrypter> Decrypters { get; private set; }
        public List<IDecryptionSetupViewModel> DecrypterViewModels { get; private set; }

        private IDecrypter currentDecrypter;
        public IDecrypter CurrentDecrypter {
            get {
                return currentDecrypter;
            }
            set {
                currentDecrypter = value;
                decryptedText.CurrentDecrypter = value;
                OnPropertyChanged("CurrentDecrypter");
                SetCorrespondingViewModel(currentDecrypter);
            }
        }

        private IDecryptionSetupViewModel currentDecrypterViewModel;
        public IDecryptionSetupViewModel CurrentDecrypterViewModel {
            get {
                return currentDecrypterViewModel;
            }
            set {
                currentDecrypterViewModel = value;
                OnPropertyChanged("CurrentDecrypterViewModel");
            }
        }

        public string ActiveAlgorithmName {
            get {
                return CurrentDecrypter.ToString();
            }
        }

        public DecrypterViewModel(IObservableText encryptedText, IDecryptedText decryptedText, params Tuple<IDecrypter, IDecryptionSetupViewModel>[] decryptionAlgorithmsVMPairs) {
            this.encryptedText = encryptedText;
            this.decryptedText = decryptedText;
            encryptedText.TextChanged += (s, e) => OnPropertyChanged("EncryptedText");
            decryptedText.TextChanged += (s, e) => OnPropertyChanged("DecryptedText");
            InitialiseDecryptersAndViewModels(decryptionAlgorithmsVMPairs);
        }

        private void InitialiseDecryptersAndViewModels(Tuple<IDecrypter, IDecryptionSetupViewModel>[] decryptionAlgorithmsVMPairs) {
            Decrypters = new List<IDecrypter>();
            DecrypterViewModels = new List<IDecryptionSetupViewModel>();
            foreach (var decryptionAlgorithmVMPair in decryptionAlgorithmsVMPairs) {
                Decrypters.Add(decryptionAlgorithmVMPair.Item1);
                DecrypterViewModels.Add(decryptionAlgorithmVMPair.Item2);
            }

            CurrentDecrypter = Decrypters[0];
            CurrentDecrypterViewModel = DecrypterViewModels[0];
        }

        private void SetCorrespondingViewModel(IDecrypter decryptionAlgorithm) {
            var decryptionAlgorithmIndex = Decrypters.FindIndex(x => x == decryptionAlgorithm);
            CurrentDecrypterViewModel = DecrypterViewModels[decryptionAlgorithmIndex];
        }
    }
}
