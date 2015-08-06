using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Algorithms;
using Decryption.Models;

namespace DecryptionUnitTests {
    [TestClass]
    public class MonoAlphaDecrypterUnitTest {
        private MonoAlphaDecrypter target;

        [TestInitialize]
        public void Initialize() {
            target = new MonoAlphaDecrypter();
        }

        [TestMethod]
        public void ShouldDecryptTextUsingMonoAlphaDecryptionAlgorithm() {
            var substitutionPairs = new Dictionary<char, char> {
                { 'j', 't' }, { 'c', 'a' }, { 's', 'r' }, { 'i', 'o' }, { 'f', 's' }, { 'g', 'n' }, { 'b', 'e' }
            };
            foreach (var pair in substitutionPairs) {
                target.LoadSubstitutionPair(pair.Key, pair.Value);
            }

            Assert.AreEqual(
                Algorithms.MonoAlphaDecryption("fjcsisfjigb", substitutionPairs),
                target.DecryptText("fjcsisfjigb"));
        }

        [TestMethod]
        public void ShouldLeaveSpacesUntouchedByDefault() {
            target.LoadSubstitutionPair('j', 't');
            target.LoadSubstitutionPair('c', 'a');
            target.LoadSubstitutionPair('s', 'r');
            target.LoadSubstitutionPair('i', 'o');
            target.LoadSubstitutionPair('f', 's');
            target.LoadSubstitutionPair('g', 'n');
            target.LoadSubstitutionPair('b', 'e');

            Assert.AreEqual("star or stone", target.DecryptText("fjcs is fjigb"));
        }

        [TestMethod]
        public void ShouldReturnCorrectNameOnToString() {
            Assert.AreEqual("MonoAlpha", target.ToString());
        }

        [TestMethod]
        public void ShouldRaiseEncryptionChangedWhenSubstitutionPairLoaded() {
            var encryptionChangedRaised = false;
            target.EncryptionChanged += (s, e) => encryptionChangedRaised = true;

            target.LoadSubstitutionPair('a', 'b');

            Assert.IsTrue(encryptionChangedRaised);
        }
    }
}
