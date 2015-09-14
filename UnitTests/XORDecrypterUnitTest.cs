using System;
using System.Linq;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Interfaces;
using Decryption.Algorithms;
using Decryption.Models;
using Rhino.Mocks;

namespace DecryptionUnitTests {
    [TestClass]
    public class XORDecrypterUnitTest {
        private XORDecrypter target;

        private IObservableText encryptedText;
        private ITextHelper textHelper;
        private IXORKeyFinderFactory xorKeyFinderFactory;
        private IXORKeyFinder xorKeyFinder;

        [TestInitialize]
        public void Initialize() {
            encryptedText = MockRepository.GenerateMock<IObservableText>();
            textHelper = MockRepository.GenerateMock<ITextHelper>();
            xorKeyFinderFactory = MockRepository.GenerateMock<IXORKeyFinderFactory>();
            xorKeyFinder = MockRepository.GenerateMock<IXORKeyFinder>();
            xorKeyFinderFactory.Stub(x => x.Create(null, null, 0, 0)).IgnoreArguments().Return(xorKeyFinder);

            target = new XORDecrypter(encryptedText, textHelper, xorKeyFinderFactory);
        }

        [TestMethod]
        public void ShouldReturnCorrectNameOnToString() {
            Assert.AreEqual("XOR", target.ToString());
        }

        [TestMethod]
        public void ShouldRaiseEncryptionAndKeyChangedWhenKeyChanged() {
            var encryptionChangedRaised = false;
            var keyChangedRaised = false;
            target.EncryptionChanged += (s, e) => encryptionChangedRaised = true;
            target.KeyChanged += (s, e) => keyChangedRaised = true;

            SetTargetKey(42, 43, 44);

            Assert.IsTrue(encryptionChangedRaised);
            Assert.IsTrue(keyChangedRaised);
        }

        [TestMethod]
        public void ShouldUseXORKeyFinderFactoryToCreateXORKeyFinder() {
            byte lowerKeyBound = 3;
            byte upperKeyBound = 123;
            var wordsToFind = new string[] { "one", "two", "three" };
            xorKeyFinderFactory.BackToRecord();
            xorKeyFinderFactory.Expect(x => x.Create(encryptedText, textHelper, lowerKeyBound, upperKeyBound, wordsToFind)).Return(xorKeyFinder);
            xorKeyFinderFactory.Replay();
            var dummyKey = new byte[1];
            xorKeyFinder.Stub(x => x.FindNextKeyAsync(null, s => string.Empty, b => { })).IgnoreArguments().Return(Task.FromResult<byte[]>(dummyKey));

            target.FindKey(lowerKeyBound, upperKeyBound, wordsToFind);

            xorKeyFinderFactory.VerifyAllExpectations();
        }

        [TestMethod]
        public void ShouldUseXORKeyFinderToFindKey() {
            var expectedKey = new byte[1];
            xorKeyFinder.Expect(x => x.FindNextKeyAsync(null, s => s, b => { }))
                .IgnoreArguments()
                .Return(Task.FromResult<byte[]>(expectedKey));

            target.FindKey(1, 2);

            Assert.AreSame(expectedKey, target.Key);
        }

        [TestMethod]
        public void ShouldPassKeyToXORKeyFinder() {
            var dummyKey = new byte[1];
            target.Key = dummyKey;
            xorKeyFinder
                .Expect(x => x.FindNextKeyAsync(
                    Arg<byte[]>.Is.Equal(dummyKey),
                    Arg<Func<string, string>>.Is.Anything,
                    Arg<Action<byte[]>>.Is.Anything))
                .Return(Task.FromResult<byte[]>(dummyKey));

            target.FindKey(1, 2);

            xorKeyFinder.VerifyAllExpectations();
        }

        [TestMethod]
        public void ShouldPassDecryptionDelegateToXORKeyFinder() {
            var dummyKey = new byte[] {23, 32, 42, 200, 219 };
            Func<string, string> decryptDelegatePassedToKeyFinder = null;
            xorKeyFinder.Stub(x => x.FindNextKeyAsync(null, s => s, b => { }))
                .IgnoreArguments()
                .WhenCalled(x => {
                    decryptDelegatePassedToKeyFinder = x.Arguments[1] as Func<string, string>;
                })
                .Return(Task.FromResult<byte[]>(dummyKey));

            target.FindKey(1, 2);

            Assert.IsNotNull(decryptDelegatePassedToKeyFinder);
            Assert.AreEqual(
                Algorithms.XORDecryption("68,69,73,186,190,99,0,103,173,168,100,65,77,173", 23, 32, 42, 200, 219),
                decryptDelegatePassedToKeyFinder("68,69,73,186,190,99,0,103,173,168,100,65,77,173"));
        }

        [TestMethod]
        public void ShouldPassUpdateKeyDelegateToXORKeyFinder() {
            var dummyKey = new byte[] { 23, 32, 42, 200, 219 };
            Action<byte[]> updateDelegatePassedToKeyFinder = null;
            xorKeyFinder.Stub(x => x.FindNextKeyAsync(null, s => s, b => { }))
                .IgnoreArguments()
                .WhenCalled(x => {
                    updateDelegatePassedToKeyFinder = x.Arguments[2] as Action<byte[]>;
                })
                .Return(Task.FromResult<byte[]>(dummyKey));

            target.FindKey(1, 2);

            Assert.IsNotNull(updateDelegatePassedToKeyFinder);
            var dummyByteArray = new byte[] { 1, 2, 3 };
            updateDelegatePassedToKeyFinder(dummyByteArray);
            Assert.AreEqual(dummyByteArray, target.Key);
        }

        [TestMethod]
        public void ShouldUseXORAlgorithmToDecryptText() {
            SetTargetKey(23, 32, 42, 200, 219);

            Assert.AreEqual(
                target.DecryptText("68,69,73,186,190,99,0,103,173,168,100,65,77,173"),
                Algorithms.XORDecryption("68,69,73,186,190,99,0,103,173,168,100,65,77,173", 23, 32, 42, 200, 219)
            );
        }

        private void SetTargetKey(params byte[] keyValues) {
            target.Key = keyValues;
        }

        private void StubXORKeyFinderFactoryToReturn(IXORKeyFinder xorKeyFinder) {
            xorKeyFinderFactory.Stub(x => x.Create(null, null, 0, 0)).IgnoreArguments().Return(xorKeyFinder);
        }
    }
}
