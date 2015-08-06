using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Windows.Input;
using System.Threading.Tasks;
using Decryption.Common;
using Decryption.Interfaces;

namespace Decryption.ViewModels {
    class MonoAlphaSetupViewModel : ModelBase, IDecryptionSetupViewModel {
        private readonly IDecrypter decrypter;
        private readonly IObservableText encryptedText;

        public ICommand LoadSampleTextCommand { get; private set; }

        public string Name {
            get {
                return decrypter.ToString();
            }
        }

        /// <summary>
        /// Returns a dictionary of all the characters in the encrypted text along with their frequencies.
        /// </summary>
        public IDictionary<char, double> InputCharacterSet {
            get {
                if (encryptedText.Text != null) {
                    return encryptedText.Text
                        .Distinct()
                        .Select(x => new {
                            character = x,
                            frequency =  (encryptedText.Text.Count(y => y == x) / (double)encryptedText.Text.Count()) * 100
                        })
                        .OrderByDescending(x => x.frequency)
                        .ToDictionary(x => x.character, x => x.frequency);
                }

                return null;
            }
        }

        public MonoAlphaSetupViewModel(IDecrypter decrypter, IObservableText encryptedText) {
            this.decrypter = decrypter;
            this.encryptedText = encryptedText;
            LoadSampleTextCommand = new SimpleDelegateCommand(LoadSampleText);
            encryptedText.TextChanged += OnEncryptedTextChanged;
        }

        private void OnEncryptedTextChanged(object sender, EventArgs e) {
            OnPropertyChanged("InputCharacterSet");
        }

        private void LoadSampleText() {
            encryptedText.Text = Properties.Resources.SampleMonoAlphaText;
        }
    }
}
