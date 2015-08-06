using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Interfaces;
using Decryption.ViewModels;
using Rhino.Mocks;

namespace DecryptionUnitTests {
    [TestClass]
    public class XORSetupViewModelUnitTest {
        private XORSetupViewModel target;

        private IXORDecrypter decrypter;
        private IObservableText observableText;

        [TestInitialize]
        public void Initialize() {
            decrypter = MockRepository.GenerateMock<IXORDecrypter>();
            observableText = MockRepository.GenerateMock<IObservableText>();

            target = new XORSetupViewModel(decrypter, observableText);
        }

        [TestMethod]
        public void ShouldConvertKeyToASCIIBytesAndSetOnDecrypterDepenency() {
            decrypter.Expect(x => x.Key = Encoding.ASCII.GetBytes("abc"));

            target.Key = "abc";

            decrypter.VerifyAllExpectations();
        }

        [TestMethod]
        public void ShouldGetKeyFromDecrypterDepenencyAndConvertKeyFromASCIIBytes() {
            decrypter.Expect(x => x.Key).Return(Encoding.ASCII.GetBytes("abc"));

            Assert.AreEqual("abc", target.Key);

            decrypter.VerifyAllExpectations();
        }

        [TestMethod]
        public void ShouldRaiseKeyPropertyChangedWhenDecrypterRaisesKeyChanged() {
            var propertyChanged = false;
            var propertyChangedName = string.Empty;
            target.PropertyChanged += (s, e) => {
                propertyChanged = true;
                propertyChangedName = e.PropertyName;
            };

            decrypter.Raise(x => x.KeyChanged += null, null, null);

            Assert.IsTrue(propertyChanged);
            Assert.AreEqual("Key", propertyChangedName);
        }

        [TestMethod]
        public void ShouldFindKeyUsingDecrypterSupplyingCorrectArguments() {
            target.KeyAutoSearchLowerBound = 45;
            target.KeyAutoSearchUpperBound = 123;
            target.WordsToFind = "one , two,   three";
            decrypter.Expect(x => x.FindKey(45, 123, new string[]{"one", "two", "three"}));

            target.FindKeyCommand.Execute(null);

            decrypter.VerifyAllExpectations();
        }

        [TestMethod]
        public void ShouldLoadSampleTextUsingCommand() {
            observableText.Expect(x => x.Text = Arg<string>.Is.Anything);

            target.LoadSampleTextCommand.Execute(null);

            observableText.VerifyAllExpectations();
        }
    }
}
