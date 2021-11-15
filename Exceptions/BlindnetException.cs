using System;

namespace Blindnet.Exceptions
{
    public class BlindnetException : Exception
    {
        public BlindnetException()
        {
        }

        public BlindnetException(string message)
            : base(message)
        {
        }

        public BlindnetException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}