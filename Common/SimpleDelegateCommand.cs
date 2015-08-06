using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace Decryption.Common {
    public class SimpleDelegateCommand : ICommand {
        Action executeDelegate;
        Func<bool> canExecute;

        public SimpleDelegateCommand(Action executeDelegate)
            : this(executeDelegate, () => true) {
        }

        public SimpleDelegateCommand(Action executeDelegate, Func<bool> canExecute) {
            this.executeDelegate = executeDelegate;
            this.canExecute = canExecute;
        }

        public void Execute(object parameter) {
            executeDelegate();
        }

        public bool CanExecute(object parameter) {
            return canExecute();
        }

        public event EventHandler CanExecuteChanged;

        protected void OnCanExecuteChanged() {
            if (this.CanExecuteChanged != null)
                this.CanExecuteChanged(this, new EventArgs());
        }
    }
}
