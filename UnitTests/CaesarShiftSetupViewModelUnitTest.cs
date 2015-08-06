using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Interfaces;
using Decryption.ViewModels;
using Rhino.Mocks;

namespace DecryptionUnitTests {
    [TestClass]
    public class CaesarShiftSetupViewModelUnitTest {
        private CaesarShiftSetupViewModel target;

        private ICaesarShiftDecrypter decrypter;
        private IObservableText observableText;

        [TestInitialize]
        public void Initialize() {
            decrypter = MockRepository.GenerateMock<ICaesarShiftDecrypter>();
            observableText = MockRepository.GenerateMock<IObservableText>();

            target = new CaesarShiftSetupViewModel(decrypter, observableText);
        }

        [TestMethod]
        public void TestIncrementShiftUsingShiftUpCommand() {
            decrypter.Expect(x => x.Shift).Return(3);
            decrypter.Expect(x => x.Shift = 4);

            target.ShiftUpCommand.Execute(null);

            decrypter.VerifyAllExpectations();
        }

        [TestMethod]
        public void TestDecrementShiftUsingShiftDownCommand() {
            decrypter.Expect(x => x.Shift).Return(3);
            decrypter.Expect(x => x.Shift = 2);

            target.ShiftDownCommand.Execute(null);

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
