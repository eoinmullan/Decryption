using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Interfaces;
using Decryption.ViewModels;
using Rhino.Mocks;

namespace DecryptionUnitTests {
    [TestClass]
    public class DecrypterViewModelUnitTest {
        private DecrypterViewModel target;

        private IObservableText encryptedText;
        private IDecryptedText decryptedText;
        Tuple<IDecrypter, IDecryptionSetupViewModel>[] decryptersAndViewModels;

        [TestInitialize]
        public void Initialize() {
            encryptedText = MockRepository.GenerateMock<IObservableText>();
            decryptedText = MockRepository.GenerateMock<IDecryptedText>();
            SetupDecrypterAndViewModelTuples(4);

            target = new DecrypterViewModel(encryptedText, decryptedText, decryptersAndViewModels);
        }

        [TestMethod]
        public void ShouldAddAllDecryptersOnConstruction() {
            CollectionAssert.AreEqual(decryptersAndViewModels.Select(x => x.Item1).ToList(), target.Decrypters);
        }

        [TestMethod]
        public void ShouldAddAllDecrypterViewMOdelsOnConstruction() {
            CollectionAssert.AreEqual(decryptersAndViewModels.Select(x => x.Item2).ToList(), target.DecrypterViewModels);
        }

        [TestMethod]
        public void ShouldSelectFirstDecrypterandViewModelOnConstruction() {
            Assert.AreEqual(decryptersAndViewModels[0].Item1, target.CurrentDecrypter);
            Assert.AreEqual(decryptersAndViewModels[0].Item2, target.CurrentDecrypterViewModel);
        }

        [TestMethod]
        public void ShouldSetCorrespondingViewModelWhenNewDecrypterIsSet() {
            target.CurrentDecrypter = decryptersAndViewModels[1].Item1;

            Assert.AreEqual(decryptersAndViewModels[1].Item2, target.CurrentDecrypterViewModel);
        }

        [TestMethod]
        public void ShouldSetDecrypterOnDecryptedText() {
            decryptedText.Expect(x => x.CurrentDecrypter = decryptersAndViewModels[1].Item1);

            target.CurrentDecrypter = decryptersAndViewModels[1].Item1;

            decryptedText.VerifyAllExpectations();
        }

        [TestMethod]
        public void ShouldRaiseEncryptedTextPropertyChangedWhenEncryptedTextRaisesTextChanged() {
            var propertyChanged = false;
            var propertyChangedName = string.Empty;
            target.PropertyChanged += (s, e) => {
                propertyChanged = true;
                propertyChangedName = e.PropertyName;
            };

            encryptedText.Raise(x => x.TextChanged += null, null, null);

            Assert.IsTrue(propertyChanged);
            Assert.AreEqual("EncryptedText", propertyChangedName);
        }

        [TestMethod]
        public void ShouldRaiseDecryptedTextPropertyChangedWhenDecryptedTextRaisesTextChanged() {
            var propertyChanged = false;
            var propertyChangedName = string.Empty;
            target.PropertyChanged += (s, e) => {
                propertyChanged = true;
                propertyChangedName = e.PropertyName;
            };

            decryptedText.Raise(x => x.TextChanged += null, null, null);

            Assert.IsTrue(propertyChanged);
            Assert.AreEqual("DecryptedText", propertyChangedName);
        }

        private void SetupDecrypterAndViewModelTuples(int numTuples) {
            var newDecryptersAndViewModels = new List<Tuple<IDecrypter, IDecryptionSetupViewModel>>();

            for (var i = 0; i < numTuples; i++) {
                newDecryptersAndViewModels.Add(Tuple.Create(MockRepository.GenerateMock<IDecrypter>(), MockRepository.GenerateMock<IDecryptionSetupViewModel>()));
            }

            decryptersAndViewModels = newDecryptersAndViewModels.ToArray();
        }
    }
}
