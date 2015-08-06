using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Interfaces;
using Decryption.ViewModels;
using Rhino.Mocks;

namespace DecryptionUnitTests {
    [TestClass]
    public class MonoAlphaSetupViewModelUnitTest {
        private IDecrypter decrypter;
        private IObservableText inputText;
        private readonly string dummyText = "bbbbcccaad";

        MonoAlphaSetupViewModel target;

        [TestInitialize]
        public void Initialize() {
            decrypter = MockRepository.GenerateMock<IDecrypter>();
            inputText = MockRepository.GenerateMock<IObservableText>();
            inputText.Stub(x => x.Text).Return(dummyText);

            target = new MonoAlphaSetupViewModel(decrypter, inputText);
        }

        [TestMethod]
        public void ShouldCalculateFrequenciesOfInputCharacters() {
            var characterFrequencies = target.InputCharacterSet;

            Assert.AreEqual(4, characterFrequencies.Count);
            CollectionAssert.AreEqual(new List<char>() { 'b', 'c', 'a', 'd' }, characterFrequencies.Keys.ToList());
            Assert.AreEqual(40.0, characterFrequencies['b'], 0.0001);
            Assert.AreEqual(30.0, characterFrequencies['c'], 0.0001);
            Assert.AreEqual(20.0, characterFrequencies['a'], 0.0001);
            Assert.AreEqual(10.0, characterFrequencies['d'], 0.0001);
        }
    }
}
