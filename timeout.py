import signal
import sys


class timeout:
    def __init__(self, seconds):
        self.seconds = seconds

    # to use the with() syntax
    def __enter__(self):
        try:
            signal.signal(signal.SIGALRM, self.onAlarm)
        # this could be made to default to no timeout on non-UNIX systems..
        except ValueError:
            sys.exit("Could not set an alarm. (UNIX-only feature)")
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)  # 0 cancels any alarms previously set

    def onAlarm(self, signum, stackframe):  # signal handler
        raise TimeoutError()  # catch this in main program
